use crate::constants::{const_non_interactive, const_x_coordinate};
use crate::curve::{
    curve_generator, point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurvePointSize,
    CurveScalar,
};
use crate::keys::{UmbralPrivateKey, UmbralPublicKey, UmbralSignature};
use crate::params::UmbralParameters;
use crate::random_oracles::hash_to_scalar;

#[cfg(feature = "std")]
use std::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

#[derive(Clone, Debug)]
pub struct KFragProof {
    pub point_commitment: CurvePoint,
    signature_for_proxy: UmbralSignature,
    signature_for_bob: UmbralSignature,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
}

impl KFragProof {
    fn new(
        params: &UmbralParameters,
        kfrag_id: &CurveScalar,
        kfrag_bn_key: &CurveScalar,
        kfrag_point_precursor: &CurvePoint,
        signing_privkey: &UmbralPrivateKey,
        delegating_pubkey: &UmbralPublicKey,
        receiving_pubkey: &UmbralPublicKey,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let commitment = &params.u * &kfrag_bn_key;

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_bob = scalar_to_bytes(&kfrag_id)
            .concat(delegating_pubkey.to_bytes())
            .concat(receiving_pubkey.to_bytes())
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&kfrag_point_precursor));
        let signature_for_bob = signing_privkey.sign(&validity_message_for_bob);

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_proxy = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&kfrag_point_precursor))
            .concat([sign_delegating_key as u8].into())
            .concat([sign_receiving_key as u8].into());

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.
        // TODO: question for @dnunez, @tux: is it safe to attach dummy keys to a message like that?

        let validity_message_for_proxy =
            validity_message_for_proxy.concat(if sign_delegating_key {
                delegating_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let validity_message_for_proxy = validity_message_for_proxy.concat(if sign_receiving_key {
            receiving_pubkey.to_bytes()
        } else {
            GenericArray::<u8, CurvePointSize>::default()
        });

        let signature_for_proxy = signing_privkey.sign(&validity_message_for_proxy);

        Self {
            point_commitment: commitment,
            signature_for_proxy: signature_for_proxy.clone(),
            signature_for_bob: signature_for_bob.clone(),
            sign_delegating_key,
            sign_receiving_key,
        }
    }

    pub fn signature_for_bob(&self) -> UmbralSignature {
        self.signature_for_bob.clone()
    }
}

#[derive(Clone, Debug)]
pub struct KFrag {
    params: UmbralParameters,
    pub id: CurveScalar, // TODO: just bytes in the original, but judging by how it's created, seems to be a Scalar
    pub bn_key: CurveScalar,
    pub point_precursor: CurvePoint,
    pub proof: KFragProof,
}

impl KFrag {
    fn new(
        factory_base: &KFragFactoryBase,
        coefficients: &dyn KFragCoefficients,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = random_scalar();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let customization_string = const_x_coordinate().concat(scalar_to_bytes(&kfrag_id));
        let share_index = hash_to_scalar(
            &[
                factory_base.precursor,
                factory_base.bob_pubkey_point,
                factory_base.dh_point,
            ],
            Some(&customization_string),
        );

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = coefficients.poly_eval(&share_index);

        let proof = KFragProof::new(
            &factory_base.params,
            &kfrag_id,
            &rk,
            &factory_base.precursor,
            &factory_base.signer,
            &factory_base.delegating_pubkey,
            &factory_base.receiving_pubkey,
            sign_delegating_key,
            sign_receiving_key,
        );

        Self {
            params: factory_base.params,
            id: kfrag_id,
            bn_key: rk,
            point_precursor: factory_base.precursor,
            proof
        }
    }

    // FIXME: should it be constant-time?
    pub fn verify(
        &self,
        signing_pubkey: &UmbralPublicKey,
        delegating_pubkey: Option<&UmbralPublicKey>,
        receiving_pubkey: Option<&UmbralPublicKey>,
    ) -> bool {
        if self.proof.sign_delegating_key {
            // TODO: how to handle it better?
            assert!(delegating_pubkey.is_some());
        }

        if self.proof.sign_receiving_key {
            // TODO: how to handle it better?
            assert!(receiving_pubkey.is_some());
        }

        let u = self.params.u;

        let kfrag_id = self.id;
        let key = self.bn_key;
        let commitment = self.proof.point_commitment;
        let precursor = self.point_precursor;

        // We check that the commitment is well-formed
        let correct_commitment = commitment == &u * &key;

        // TODO: hide this in a special mutable object associated with Signer?
        let kfrag_validity_message = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&precursor))
            .concat([self.proof.sign_delegating_key as u8].into())
            .concat([self.proof.sign_receiving_key as u8].into());

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.

        let kfrag_validity_message =
            kfrag_validity_message.concat(if self.proof.sign_delegating_key {
                delegating_pubkey.unwrap().to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let kfrag_validity_message =
            kfrag_validity_message.concat(if self.proof.sign_receiving_key {
                receiving_pubkey.unwrap().to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let valid_kfrag_signature =
            signing_pubkey.verify(&kfrag_validity_message, &self.proof.signature_for_proxy);

        return correct_commitment & valid_kfrag_signature;
    }
}

pub struct KFragFactoryBase {
    signer: UmbralPrivateKey,
    precursor: CurvePoint,
    bob_pubkey_point: CurvePoint,
    dh_point: CurvePoint,
    params: UmbralParameters,
    delegating_pubkey: UmbralPublicKey,
    receiving_pubkey: UmbralPublicKey,
    coefficient0: CurveScalar,
}

impl KFragFactoryBase {
    pub fn new(
        params: &UmbralParameters,
        delegating_privkey: &UmbralPrivateKey,
        receiving_pubkey: &UmbralPublicKey,
        signer: &UmbralPrivateKey,
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
        let coefficient0 = &delegating_privkey.bn_key * &(d.invert().unwrap());

        Self {
            signer: *signer,
            precursor,
            bob_pubkey_point,
            dh_point,
            params: *params,
            delegating_pubkey: delegating_pubkey,
            receiving_pubkey: *receiving_pubkey,
            coefficient0,
        }
    }
}

// Coefficients of the generating polynomial
trait KFragCoefficients {
    fn coefficients(&self) -> &[CurveScalar];

    fn poly_eval(&self, x: &CurveScalar) -> CurveScalar {
        let coeffs = self.coefficients();
        let mut result: CurveScalar = coeffs[coeffs.len() - 1];
        for i in (0..coeffs.len() - 1).rev() {
            result = (&result * &x) + &coeffs[i];
        }
        result
    }
}

struct KFragCoefficientsHeapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    GenericArray<CurveScalar, Threshold>,
);

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KFragCoefficientsHeapless<Threshold> {
    fn new(coeff0: &CurveScalar) -> Self {
        let mut coefficients = GenericArray::<CurveScalar, Threshold>::default();
        coefficients[0] = *coeff0;
        for i in 1..<Threshold as Unsigned>::to_usize() {
            coefficients[i] = random_scalar();
        }
        Self(coefficients)
    }
}

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KFragCoefficients
    for KFragCoefficientsHeapless<Threshold>
{
    fn coefficients(&self) -> &[CurveScalar] {
        &self.0
    }
}

#[cfg(feature = "std")]
struct KFragCoefficientsHeap(Vec<CurveScalar>);

#[cfg(feature = "std")]
impl KFragCoefficientsHeap {
    fn new(coeff0: &CurveScalar, threshold: usize) -> Self {
        let mut coefficients = Vec::<CurveScalar>::with_capacity(threshold - 1);
        coefficients.push(*coeff0);
        for _i in 1..threshold {
            coefficients.push(random_scalar());
        }
        Self(coefficients)
    }
}

#[cfg(feature = "std")]
impl KFragCoefficients for KFragCoefficientsHeap {
    fn coefficients(&self) -> &[CurveScalar] {
        &self.0
    }
}

pub struct KFragFactoryHeapless<Threshold: ArrayLength<CurveScalar> + Unsigned> {
    base: KFragFactoryBase,
    coefficients: KFragCoefficientsHeapless<Threshold>,
}

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KFragFactoryHeapless<Threshold> {
    pub fn new(
        params: &UmbralParameters,
        delegating_privkey: &UmbralPrivateKey,
        receiving_pubkey: &UmbralPublicKey,
        signer: &UmbralPrivateKey,
    ) -> Self {
        let base = KFragFactoryBase::new(params, delegating_privkey, receiving_pubkey, signer);
        let coefficients = KFragCoefficientsHeapless::<Threshold>::new(&base.coefficient0);
        Self { base, coefficients }
    }

    pub fn make(&self, sign_delegating_key: bool, sign_receiving_key: bool) -> KFrag {
        KFrag::new(
            &self.base,
            &self.coefficients,
            sign_delegating_key,
            sign_receiving_key,
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
pub fn generate_kfrags(
    params: &UmbralParameters,
    delegating_privkey: &UmbralPrivateKey,
    receiving_pubkey: &UmbralPublicKey,
    threshold: usize,
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

    let base = KFragFactoryBase::new(params, delegating_privkey, receiving_pubkey, signer);

    let coefficients = KFragCoefficientsHeap::new(&base.coefficient0, threshold);

    let mut result = Vec::<KFrag>::new();
    for _ in 0..num_kfrags {
        result.push(KFrag::new(
            &base,
            &coefficients,
            sign_delegating_key,
            sign_receiving_key,
        ));
    }

    result
}
