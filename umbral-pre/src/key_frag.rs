use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{CurvePoint, CurveScalar};
use crate::curve::{UmbralPublicKey, UmbralSecretKey, UmbralSignature};
use crate::hashing::{ScalarDigest, SignatureDigest};
use crate::params::UmbralParameters;
use crate::traits::SerializableToArray;

use alloc::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::{op, U1};

#[derive(Clone, Debug)]
pub struct KeyFragProof {
    pub commitment: CurvePoint,
    signature_for_proxy: UmbralSignature,
    signature_for_bob: UmbralSignature,
    delegating_key_signed: bool,
    receiving_key_signed: bool,
}

type ParametersSize = <UmbralParameters as SerializableToArray>::Size;
type SignatureSize = <UmbralSignature as SerializableToArray>::Size;
type ScalarSize = <CurveScalar as SerializableToArray>::Size;
type PointSize = <CurvePoint as SerializableToArray>::Size;
type KeyFragProofSize = op!(PointSize + SignatureSize + SignatureSize + U1 + U1);

impl SerializableToArray for KeyFragProof {
    type Size = KeyFragProofSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.commitment
            .to_array()
            .concat(self.signature_for_proxy.to_array())
            .concat(self.signature_for_bob.to_array())
            .concat(self.delegating_key_signed.to_array())
            .concat(self.receiving_key_signed.to_array())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let (commitment, rest) = CurvePoint::take(*arr)?;
        let (signature_for_proxy, rest) = UmbralSignature::take(rest)?;
        let (signature_for_bob, rest) = UmbralSignature::take(rest)?;
        let (delegating_key_signed, rest) = bool::take(rest)?;
        let receiving_key_signed = bool::take_last(rest)?;
        Some(Self {
            commitment,
            signature_for_proxy,
            signature_for_bob,
            delegating_key_signed,
            receiving_key_signed,
        })
    }
}

impl KeyFragProof {
    #[allow(clippy::too_many_arguments)]
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
        let commitment = &params.u * kfrag_key;

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

type KeyFragSize = op!(ParametersSize + ScalarSize + ScalarSize + PointSize + KeyFragProofSize);

impl SerializableToArray for KeyFrag {
    type Size = KeyFragSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.params
            .to_array()
            .concat(self.id.to_array())
            .concat(self.key.to_array())
            .concat(self.precursor.to_array())
            .concat(self.proof.to_array())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let (params, rest) = UmbralParameters::take(*arr)?;
        let (id, rest) = CurveScalar::take(rest)?;
        let (key, rest) = CurveScalar::take(rest)?;
        let (precursor, rest) = CurvePoint::take(rest)?;
        let proof = KeyFragProof::take_last(rest)?;
        Some(Self {
            params,
            id,
            key,
            precursor,
            proof,
        })
    }
}

impl KeyFrag {
    fn new(factory: &KeyFragFactory, sign_delegating_key: bool, sign_receiving_key: bool) -> Self {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = CurveScalar::random_nonzero();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let share_index = ScalarDigest::new()
            .chain_points(&[
                factory.precursor,
                factory.bob_pubkey_point,
                factory.dh_point,
            ])
            .chain_bytes(X_COORDINATE)
            .chain_scalar(&kfrag_id)
            .finalize();

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = poly_eval(&factory.coefficients, &share_index);

        let proof = KeyFragProof::new(
            &factory.params,
            &kfrag_id,
            &rk,
            &factory.precursor,
            &factory.signing_privkey,
            &factory.delegating_pubkey,
            &factory.receiving_pubkey,
            sign_delegating_key,
            sign_receiving_key,
        );

        Self {
            params: factory.params,
            id: kfrag_id,
            key: rk,
            precursor: factory.precursor,
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

struct KeyFragFactory {
    signing_privkey: UmbralSecretKey,
    precursor: CurvePoint,
    bob_pubkey_point: CurvePoint,
    dh_point: CurvePoint,
    params: UmbralParameters,
    delegating_pubkey: UmbralPublicKey,
    receiving_pubkey: UmbralPublicKey,
    coefficients: Vec<CurveScalar>,
}

impl KeyFragFactory {
    pub fn new(
        params: &UmbralParameters,
        delegating_privkey: &UmbralSecretKey,
        receiving_pubkey: &UmbralPublicKey,
        signing_privkey: &UmbralSecretKey,
        threshold: usize,
    ) -> Self {
        let g = CurvePoint::generator();

        let delegating_pubkey = UmbralPublicKey::from_secret_key(delegating_privkey);

        let bob_pubkey_point = receiving_pubkey.to_point();

        // The precursor point is used as an ephemeral public key in a DH key exchange,
        // and the resulting shared secret 'dh_point' is used to derive other secret values
        let private_precursor = CurveScalar::random_nonzero();
        let precursor = &g * &private_precursor;

        let dh_point = &bob_pubkey_point * &private_precursor;

        // Secret value 'd' allows to make Umbral non-interactive
        let d = ScalarDigest::new()
            .chain_points(&[precursor, bob_pubkey_point, dh_point])
            .chain_bytes(NON_INTERACTIVE)
            .finalize();

        // Coefficients of the generating polynomial
        let coefficient0 = &delegating_privkey.to_secret_scalar() * &(d.invert().unwrap());

        let mut coefficients = Vec::<CurveScalar>::with_capacity(threshold);
        coefficients.push(coefficient0);
        for _i in 1..threshold {
            coefficients.push(CurveScalar::random_nonzero());
        }

        Self {
            signing_privkey: signing_privkey.clone(),
            precursor,
            bob_pubkey_point,
            dh_point,
            params: *params,
            delegating_pubkey,
            receiving_pubkey: *receiving_pubkey,
            coefficients,
        }
    }
}

// Coefficients of the generating polynomial
fn poly_eval(coeffs: &[CurveScalar], x: &CurveScalar) -> CurveScalar {
    let mut result: CurveScalar = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = &(&result * x) + &coeffs[i];
    }
    result
}

/*
Creates a re-encryption key from Alice's delegating public key to Bob's
receiving public key, and splits it in KeyFrags, using Shamir's Secret Sharing.
Requires a threshold number of KeyFrags out of N.

Returns a list of N KeyFrags
*/
#[allow(clippy::too_many_arguments)]
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

    let base = KeyFragFactory::new(
        params,
        delegating_privkey,
        receiving_pubkey,
        signing_privkey,
        threshold,
    );

    let mut result = Vec::<KeyFrag>::new();
    for _ in 0..num_kfrags {
        result.push(KeyFrag::new(&base, sign_delegating_key, sign_receiving_key));
    }

    result
}
