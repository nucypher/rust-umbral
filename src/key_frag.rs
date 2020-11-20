use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{random_nonzero_scalar, CurvePoint, CurveScalar};
use crate::keys::{UmbralPublicKey, UmbralSecretKey, UmbralSignature};
use crate::params::UmbralParameters;
use crate::random_oracles::{ScalarDigest, SignatureDigest};

#[cfg(feature = "std")]
use std::vec::Vec;

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

#[derive(Clone, Debug)]
pub struct KeyFragProof {
    pub commitment: CurvePoint,
    signature_for_proxy: UmbralSignature,
    signature_for_bob: UmbralSignature,
    delegating_key_signed: bool,
    receiving_key_signed: bool,
}

impl KeyFragProof {
    fn new(
        params: &UmbralParameters,
        kfrag_id: &CurveScalar,
        kfrag_key: &CurveScalar,
        kfrag_precursor: &CurvePoint,
        signing_privkey: &UmbralSecretKey,
        delegating_pubkey: &UmbralPublicKey,
        receiving_pubkey: &UmbralPublicKey,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let commitment = params.u * kfrag_key;

        let signature_for_bob = SignatureDigest::new()
            .chain_scalar(kfrag_id)
            .chain_pubkey(delegating_pubkey)
            .chain_pubkey(receiving_pubkey)
            .chain_point(&commitment)
            .chain_point(kfrag_precursor)
            .sign(signing_privkey);

        let mut digest_for_proxy = SignatureDigest::new()
            .chain_scalar(kfrag_id)
            .chain_point(&commitment)
            .chain_point(kfrag_precursor)
            .chain_bool(sign_delegating_key)
            .chain_bool(sign_receiving_key);

        if sign_delegating_key {
            digest_for_proxy = digest_for_proxy.chain_pubkey(delegating_pubkey);
        }

        if sign_receiving_key {
            digest_for_proxy = digest_for_proxy.chain_pubkey(receiving_pubkey);
        }

        let signature_for_proxy = digest_for_proxy.sign(&signing_privkey);

        Self {
            commitment,
            signature_for_proxy,
            signature_for_bob,
            delegating_key_signed: sign_delegating_key,
            receiving_key_signed: sign_receiving_key,
        }
    }

    pub(crate) fn signature_for_bob(&self) -> UmbralSignature {
        self.signature_for_bob.clone()
    }
}

#[derive(Clone, Debug)]
pub struct KeyFrag {
    params: UmbralParameters,
    pub(crate) id: CurveScalar, // TODO: just bytes in the original, but judging by how it's created, seems to be a Scalar
    pub(crate) key: CurveScalar,
    pub(crate) precursor: CurvePoint,
    pub(crate) proof: KeyFragProof,
}

impl KeyFrag {
    fn new(
        factory_base: &KeyFragFactoryBase,
        coefficients: &dyn KeyFragCoefficients,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = random_nonzero_scalar();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let share_index = ScalarDigest::new()
            .chain_points(&[
                factory_base.precursor,
                factory_base.bob_pubkey_point,
                factory_base.dh_point,
            ])
            .chain_bytes(X_COORDINATE)
            .chain_scalar(&kfrag_id)
            .finalize();

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = coefficients.poly_eval(&share_index);

        let proof = KeyFragProof::new(
            &factory_base.params,
            &kfrag_id,
            &rk,
            &factory_base.precursor,
            &factory_base.signing_privkey,
            &factory_base.delegating_pubkey,
            &factory_base.receiving_pubkey,
            sign_delegating_key,
            sign_receiving_key,
        );

        Self {
            params: factory_base.params,
            id: kfrag_id,
            key: rk,
            precursor: factory_base.precursor,
            proof,
        }
    }

    pub fn verify(
        &self,
        signing_pubkey: &UmbralPublicKey,
        delegating_pubkey: Option<&UmbralPublicKey>,
        receiving_pubkey: Option<&UmbralPublicKey>,
    ) -> bool {
        if self.proof.delegating_key_signed {
            // TODO: how to handle it better?
            assert!(delegating_pubkey.is_some());
        }

        if self.proof.receiving_key_signed {
            // TODO: how to handle it better?
            assert!(receiving_pubkey.is_some());
        }

        let u = self.params.u;

        let kfrag_id = self.id;
        let key = self.key;
        let commitment = self.proof.commitment;
        let precursor = self.precursor;

        // We check that the commitment is well-formed
        let correct_commitment = commitment == &u * &key;

        let mut digest = SignatureDigest::new()
            .chain_scalar(&kfrag_id)
            .chain_point(&commitment)
            .chain_point(&precursor)
            .chain_bool(self.proof.delegating_key_signed)
            .chain_bool(self.proof.receiving_key_signed);
        if self.proof.delegating_key_signed {
            digest = digest.chain_pubkey(&delegating_pubkey.unwrap());
        }
        if self.proof.receiving_key_signed {
            digest = digest.chain_pubkey(&receiving_pubkey.unwrap());
        }
        let valid_kfrag_signature = digest.verify(&signing_pubkey, &self.proof.signature_for_proxy);

        correct_commitment & valid_kfrag_signature
    }
}

struct KeyFragFactoryBase {
    signing_privkey: UmbralSecretKey,
    precursor: CurvePoint,
    bob_pubkey_point: CurvePoint,
    dh_point: CurvePoint,
    params: UmbralParameters,
    delegating_pubkey: UmbralPublicKey,
    receiving_pubkey: UmbralPublicKey,
    coefficient0: CurveScalar,
}

impl KeyFragFactoryBase {
    pub fn new(
        params: &UmbralParameters,
        delegating_privkey: &UmbralSecretKey,
        receiving_pubkey: &UmbralPublicKey,
        signing_privkey: &UmbralSecretKey,
    ) -> Self {
        let g = CurvePoint::generator();

        let delegating_pubkey = UmbralPublicKey::from_secret_key(delegating_privkey);

        let bob_pubkey_point = receiving_pubkey.to_point();

        // The precursor point is used as an ephemeral public key in a DH key exchange,
        // and the resulting shared secret 'dh_point' is used to derive other secret values
        let private_precursor = random_nonzero_scalar();
        let precursor = &g * &private_precursor;

        let dh_point = &bob_pubkey_point * &private_precursor;

        // Secret value 'd' allows to make Umbral non-interactive
        let d = ScalarDigest::new()
            .chain_points(&[precursor, bob_pubkey_point, dh_point])
            .chain_bytes(NON_INTERACTIVE)
            .finalize();

        // Coefficients of the generating polynomial
        let coefficient0 = delegating_privkey.secret_scalar() * &(d.invert().unwrap());

        Self {
            signing_privkey: signing_privkey.clone(),
            precursor,
            bob_pubkey_point,
            dh_point,
            params: *params,
            delegating_pubkey,
            receiving_pubkey: *receiving_pubkey,
            coefficient0,
        }
    }
}

// Coefficients of the generating polynomial
trait KeyFragCoefficients {
    fn coefficients(&self) -> &[CurveScalar];

    fn poly_eval(&self, x: &CurveScalar) -> CurveScalar {
        let coeffs = self.coefficients();
        let mut result: CurveScalar = coeffs[coeffs.len() - 1];
        for i in (0..coeffs.len() - 1).rev() {
            result = (result * x) + &coeffs[i];
        }
        result
    }
}

struct KeyFragCoefficientsHeapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    GenericArray<CurveScalar, Threshold>,
);

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KeyFragCoefficientsHeapless<Threshold> {
    fn new(coeff0: &CurveScalar) -> Self {
        let mut coefficients = GenericArray::<CurveScalar, Threshold>::default();
        coefficients[0] = *coeff0;
        for i in 1..<Threshold as Unsigned>::to_usize() {
            coefficients[i] = random_nonzero_scalar();
        }
        Self(coefficients)
    }
}

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KeyFragCoefficients
    for KeyFragCoefficientsHeapless<Threshold>
{
    fn coefficients(&self) -> &[CurveScalar] {
        &self.0
    }
}

#[cfg(feature = "std")]
struct KeyFragCoefficientsHeap(Vec<CurveScalar>);

#[cfg(feature = "std")]
impl KeyFragCoefficientsHeap {
    fn new(coeff0: &CurveScalar, threshold: usize) -> Self {
        let mut coefficients = Vec::<CurveScalar>::with_capacity(threshold - 1);
        coefficients.push(*coeff0);
        for _i in 1..threshold {
            coefficients.push(random_nonzero_scalar());
        }
        Self(coefficients)
    }
}

#[cfg(feature = "std")]
impl KeyFragCoefficients for KeyFragCoefficientsHeap {
    fn coefficients(&self) -> &[CurveScalar] {
        &self.0
    }
}

pub struct KeyFragFactoryHeapless<Threshold: ArrayLength<CurveScalar> + Unsigned> {
    base: KeyFragFactoryBase,
    coefficients: KeyFragCoefficientsHeapless<Threshold>,
}

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> KeyFragFactoryHeapless<Threshold> {
    pub fn new(
        params: &UmbralParameters,
        delegating_privkey: &UmbralSecretKey,
        receiving_pubkey: &UmbralPublicKey,
        signing_privkey: &UmbralSecretKey,
    ) -> Self {
        let base = KeyFragFactoryBase::new(
            params,
            delegating_privkey,
            receiving_pubkey,
            signing_privkey,
        );
        let coefficients = KeyFragCoefficientsHeapless::<Threshold>::new(&base.coefficient0);
        Self { base, coefficients }
    }

    pub fn make(&self, sign_delegating_key: bool, sign_receiving_key: bool) -> KeyFrag {
        KeyFrag::new(
            &self.base,
            &self.coefficients,
            sign_delegating_key,
            sign_receiving_key,
        )
    }
}

/*
Creates a re-encryption key from Alice's delegating public key to Bob's
receiving public key, and splits it in KeyFrags, using Shamir's Secret Sharing.
Requires a threshold number of KeyFrags out of N.

Returns a list of N KeyFrags
*/
#[cfg(feature = "std")]
pub fn generate_kfrags(
    params: &UmbralParameters,
    delegating_privkey: &UmbralSecretKey,
    receiving_pubkey: &UmbralPublicKey,
    signing_privkey: &UmbralSecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<KeyFrag> {
    assert!(threshold > 0);

    // Technically we can do threshold > num_kfrags, but the result will be useless
    assert!(threshold <= num_kfrags);

    let base = KeyFragFactoryBase::new(
        params,
        delegating_privkey,
        receiving_pubkey,
        signing_privkey,
    );

    let coefficients = KeyFragCoefficientsHeap::new(&base.coefficient0, threshold);

    let mut result = Vec::<KeyFrag>::new();
    for _ in 0..num_kfrags {
        result.push(KeyFrag::new(
            &base,
            &coefficients,
            sign_delegating_key,
            sign_receiving_key,
        ));
    }

    result
}
