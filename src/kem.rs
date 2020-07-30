use crate::capsule::{Capsule, PreparedCapsule};
use crate::cfrags::CapsuleFrag;
use crate::constants::{const_non_interactive, const_x_coordinate};
use crate::curve::{
    point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurvePointSize, CurveScalar,
};

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::dem::UmbralDEM;
use crate::keys::{UmbralPrivateKey, UmbralPublicKey};
use crate::kfrags::{key_type_to_bytes, KFrag, KeyType};
use crate::params::UmbralParameters;
use crate::random_oracles::{hash_to_scalar, kdf, KdfSize};
use crate::utils::{lambda_coeff, poly_eval};

use generic_array::sequence::Concat;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

/// Generates a symmetric key and its associated KEM ciphertext
pub fn encapsulate(alice_pubkey: &UmbralPublicKey) -> (UmbralDEM, Capsule) {
    let params = alice_pubkey.params;
    let g = params.g;

    let priv_r = random_scalar();
    let pub_r = &g * &priv_r;

    let priv_u = random_scalar();
    let pub_u = &g * &priv_u;

    let h = hash_to_scalar(&[pub_r, pub_u], None);

    let s = &priv_u + (&priv_r * &h);

    let shared_key = &(alice_pubkey.point_key) * &(&priv_r + &priv_u);

    // Key to be used for symmetric encryption
    let key = kdf(&shared_key, None, None);

    (
        UmbralDEM::new(&key),
        Capsule::new(&params, &pub_r, &pub_u, &s),
    )
}


/// Derive the same symmetric key
pub fn decapsulate_original(
    private_key: &UmbralPrivateKey,
    capsule: &Capsule,
) -> GenericArray<u8, KdfSize> {
    // TODO: capsule should be verified on creation
    //if not capsule.verify():
    //    # Check correctness of original ciphertext
    //    raise capsule.NotValid("Capsule verification failed.")

    let shared_key = (&capsule.point_e + &capsule.point_v) * &private_key.bn_key;
    kdf(&shared_key, None, None)
}


pub struct KFragFactory<Threshold: ArrayLength<CurveScalar> + Unsigned> {
    signer: UmbralPrivateKey,
    precursor: CurvePoint,
    bob_pubkey_point: CurvePoint,
    dh_point: CurvePoint,
    params: UmbralParameters,
    delegating_pubkey: UmbralPublicKey,
    receiving_pubkey: UmbralPublicKey,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
    coefficients: GenericArray<CurveScalar, Threshold>,
}

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KFragFactory<Threshold> {
    pub fn new(
        delegating_privkey: &UmbralPrivateKey,
        receiving_pubkey: &UmbralPublicKey,
        signer: &UmbralPrivateKey,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let params = delegating_privkey.params;
        let g = params.g;

        let delegating_pubkey = delegating_privkey.get_pubkey();

        let bob_pubkey_point = receiving_pubkey.point_key;

        // The precursor point is used as an ephemeral public key in a DH key exchange,
        // and the resulting shared secret 'dh_point' is used to derive other secret values
        let private_precursor = random_scalar();
        let precursor = &g * &private_precursor;

        let dh_point = &bob_pubkey_point * &private_precursor;

        // Secret value 'd' allows to make Umbral non-interactive
        let d = hash_to_scalar(
            &[precursor, bob_pubkey_point, dh_point],
            Some(&const_non_interactive()),
        );

        // Coefficients of the generating polynomial
        let mut coefficients = GenericArray::<CurveScalar, Threshold>::default();
        coefficients[0] = &delegating_privkey.bn_key * &(d.invert().unwrap());
        for i in 1..<Threshold as Unsigned>::to_usize() {
            coefficients[i] = random_scalar();
        }

        Self {
            signer: *signer,
            precursor,
            bob_pubkey_point,
            dh_point,
            params,
            delegating_pubkey: delegating_pubkey,
            receiving_pubkey: *receiving_pubkey,
            sign_delegating_key,
            sign_receiving_key,
            coefficients,
        }
    }

    pub fn make(&self) -> KFrag {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = random_scalar();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let customization_string = const_x_coordinate().concat(scalar_to_bytes(&kfrag_id));
        let share_index = hash_to_scalar(
            &[self.precursor, self.bob_pubkey_point, self.dh_point],
            Some(&customization_string),
        );

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = poly_eval(&self.coefficients, &share_index);

        let commitment = &self.params.u * &rk;

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_bob = scalar_to_bytes(&kfrag_id)
            .concat(self.delegating_pubkey.to_bytes())
            .concat(self.receiving_pubkey.to_bytes())
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&self.precursor));
        let signature_for_bob = self.signer.sign(&validity_message_for_bob);

        // TODO: can be a function where KeyType is defined
        let mode = match (self.sign_delegating_key, self.sign_receiving_key) {
            (true, true) => KeyType::DelegatingAndReceiving,
            (true, false) => KeyType::DelegatingOnly,
            (false, true) => KeyType::ReceivingOnly,
            (false, false) => KeyType::NoKey,
        };

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_proxy = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&self.precursor))
            .concat(key_type_to_bytes(&mode));

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.
        // TODO: question for @dnunez, @tux: is it safe to attach dummy keys to a message like that?

        let validity_message_for_proxy =
            validity_message_for_proxy.concat(if self.sign_delegating_key {
                self.delegating_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let validity_message_for_proxy =
            validity_message_for_proxy.concat(if self.sign_receiving_key {
                self.receiving_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let signature_for_proxy = self.signer.sign(&validity_message_for_proxy);

        KFrag::new(
            &self.params,
            &kfrag_id,
            &rk,
            &commitment,
            &self.precursor,
            &signature_for_proxy,
            &signature_for_bob,
            Some(mode),
        )
    }
}

/*
Creates a re-encryption key from Alice's delegating public key to Bob's
receiving public key, and splits it in KFrags, using Shamir's Secret Sharing.
Requires a threshold number of KFrags out of N.

Returns a list of N KFrags
*/
#[cfg(feature = "std")]
pub fn generate_kfrags<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    delegating_privkey: &UmbralPrivateKey,
    receiving_pubkey: &UmbralPublicKey,
    num_kfrags: usize,
    signer: &UmbralPrivateKey,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<KFrag> {
    // TODO: debug_assert!, or panic in release too?
    //if threshold <= 0 or threshold > N:
    //    raise ValueError('Arguments threshold and N must satisfy 0 < threshold <= N')
    //if delegating_privkey.params != receiving_pubkey.params:
    //    raise ValueError("Keys must have the same parameter set.")

    let factory = KFragFactory::<Threshold>::new(
        delegating_privkey,
        receiving_pubkey,
        signer,
        sign_delegating_key,
        sign_receiving_key,
    );

    let mut result = Vec::<KFrag>::new();
    for _ in 0..num_kfrags {
        result.push(factory.make());
    }

    result
}

pub fn reencrypt(
    kfrag: &KFrag,
    prepared_capsule: &PreparedCapsule,
    metadata: Option<&[u8]>,
    verify_kfrag: bool,
) -> Option<CapsuleFrag> {
    // TODO: verify on creation?
    //if not prepared_capsule.verify():
    //    raise Capsule.NotValid

    if verify_kfrag {
        if !prepared_capsule.verify_kfrag(&kfrag) {
            return None;
        }
    }

    Some(CapsuleFrag::from_kfrag(
        &prepared_capsule.capsule,
        &kfrag,
        metadata,
    ))
}

/// Derive the same symmetric encapsulated_key
pub fn decapsulate_reencrypted<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    receiving_privkey: &UmbralPrivateKey,
    prepared_capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
) -> GenericArray<u8, KdfSize> {
    let capsule = prepared_capsule.capsule;

    let pub_key = receiving_privkey.get_pubkey().point_key;
    let priv_key = receiving_privkey.bn_key;

    let precursor = cfrags[0].point_precursor;
    let dh_point = &precursor * &priv_key;

    // Combination of CFrags via Shamir's Secret Sharing reconstruction
    let mut xs = GenericArray::<CurveScalar, Threshold>::default();
    for (i, cfrag) in cfrags.iter().enumerate() {
        let customization_string = const_x_coordinate().concat(scalar_to_bytes(&cfrag.kfrag_id));
        xs[i] = hash_to_scalar(&[precursor, pub_key, dh_point], Some(&customization_string));
    }

    let mut e_prime = CurvePoint::identity();
    let mut v_prime = CurvePoint::identity();
    for (cfrag, x) in (&cfrags).iter().zip((&xs).iter()) {
        assert!(precursor == cfrag.point_precursor);
        let lambda_i = lambda_coeff(&x, &xs);
        e_prime += &cfrag.point_e1 * &lambda_i;
        v_prime += &cfrag.point_v1 * &lambda_i;
    }

    // Secret value 'd' allows to make Umbral non-interactive
    let d = hash_to_scalar(
        &[precursor, pub_key, dh_point],
        Some(&const_non_interactive()),
    );

    let e = capsule.point_e;
    let v = capsule.point_v;
    let s = capsule.bn_sig;
    let h = hash_to_scalar(&[e, v], None);

    let orig_pub_key = prepared_capsule.delegating_key.point_key;

    assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
    //    raise GenericUmbralError()

    let shared_key = (&e_prime + &v_prime) * &d;

    kdf(&shared_key, None, None)
}

/*
Activates the Capsule from the attached CFrags,
opens the Capsule and returns what is inside.

This will often be a symmetric key.
*/
pub fn open_capsule<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    prepared_capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    receiving_privkey: &UmbralPrivateKey,
    check_proof: bool,
) -> GenericArray<u8, KdfSize> {
    if check_proof {
        // TODO: return Result with Error set to offending cfrag indices or something
        for cfrag in cfrags {
            assert!(prepared_capsule.verify_cfrag(cfrag));
        }
    }

    decapsulate_reencrypted::<Threshold>(receiving_privkey, prepared_capsule, cfrags)
}
