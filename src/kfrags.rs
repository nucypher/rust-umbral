use crate::constants::{const_non_interactive, const_x_coordinate};
use crate::curve::{
    curve_generator, point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurvePointSize,
    CurveScalar,
};
use crate::keys::{UmbralPrivateKey, UmbralPublicKey, UmbralSignature};
use crate::params::UmbralParameters;
use crate::random_oracles::hash_to_scalar;
use crate::utils::poly_eval;

#[cfg(feature = "std")]
use std::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::typenum::{Unsigned, U1};
use generic_array::{ArrayLength, GenericArray};

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    NoKey,
    DelegatingOnly,
    ReceivingOnly,
    DelegatingAndReceiving,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::NoKey
    }
}

pub fn key_type_to_bytes(kt: &KeyType) -> GenericArray<u8, U1> {
    let slice = match kt {
        KeyType::NoKey => [0],
        KeyType::DelegatingOnly => [1],
        KeyType::ReceivingOnly => [2],
        KeyType::DelegatingAndReceiving => [3],
    };
    GenericArray::<u8, U1>::clone_from_slice(&slice)
}

fn delegating_key_in_signature(kt: &KeyType) -> bool {
    match kt {
        KeyType::DelegatingOnly => true,
        KeyType::DelegatingAndReceiving => true,
        _ => false,
    }
}

fn receiving_key_in_signature(kt: &KeyType) -> bool {
    match kt {
        KeyType::ReceivingOnly => true,
        KeyType::DelegatingAndReceiving => true,
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub struct KFrag {
    params: UmbralParameters,
    pub id: CurveScalar, // TODO: just bytes in the original, but judging by how it's created, seems to be a Scalar
    pub bn_key: CurveScalar,
    pub point_commitment: CurvePoint,
    pub point_precursor: CurvePoint,
    signature_for_proxy: UmbralSignature,
    pub signature_for_bob: UmbralSignature,
    keys_in_signature: KeyType,
}

impl KFrag {
    pub fn new(
        params: &UmbralParameters,
        id: &CurveScalar,
        bn_key: &CurveScalar,
        point_commitment: &CurvePoint,
        point_precursor: &CurvePoint,
        signature_for_proxy: &UmbralSignature,
        signature_for_bob: &UmbralSignature,
        keys_in_signature: Option<KeyType>,
    ) -> Self {
        let kt = match keys_in_signature {
            Some(k) => k,
            None => KeyType::DelegatingAndReceiving,
        };

        Self {
            params: *params,
            id: *id,
            bn_key: *bn_key,
            point_commitment: *point_commitment,
            point_precursor: *point_precursor,
            signature_for_proxy: signature_for_proxy.clone(),
            signature_for_bob: signature_for_bob.clone(),
            keys_in_signature: kt,
        }
    }

    // FIXME: should it be constant-time?
    pub fn verify(
        &self,
        signing_pubkey: &UmbralPublicKey,
        delegating_pubkey: Option<&UmbralPublicKey>,
        receiving_pubkey: Option<&UmbralPublicKey>,
    ) -> bool {
        if delegating_key_in_signature(&self.keys_in_signature) {
            // TODO: how to handle it better?
            assert!(delegating_pubkey.is_some());
        }

        if receiving_key_in_signature(&self.keys_in_signature) {
            // TODO: how to handle it better?
            assert!(receiving_pubkey.is_some());
        }

        let u = self.params.u;

        let kfrag_id = self.id;
        let key = self.bn_key;
        let commitment = self.point_commitment;
        let precursor = self.point_precursor;

        // We check that the commitment is well-formed
        let correct_commitment = commitment == &u * &key;

        // TODO: hide this in a special mutable object associated with Signer?
        let kfrag_validity_message = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&precursor))
            .concat(key_type_to_bytes(&self.keys_in_signature));

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.

        let kfrag_validity_message = kfrag_validity_message.concat(
            if delegating_key_in_signature(&self.keys_in_signature) {
                delegating_pubkey.unwrap().to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            },
        );

        let kfrag_validity_message =
            kfrag_validity_message.concat(if receiving_key_in_signature(&self.keys_in_signature) {
                receiving_pubkey.unwrap().to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let valid_kfrag_signature =
            signing_pubkey.verify(&kfrag_validity_message, &self.signature_for_proxy);

        return correct_commitment & valid_kfrag_signature;
    }
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
        params: &UmbralParameters,
        delegating_privkey: &UmbralPrivateKey,
        receiving_pubkey: &UmbralPublicKey,
        signer: &UmbralPrivateKey,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let g = curve_generator();

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
            params: *params,
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
    params: &UmbralParameters,
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
        params,
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
