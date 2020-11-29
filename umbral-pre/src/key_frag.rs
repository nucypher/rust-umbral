use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{CurvePoint, CurveScalar};
use crate::curve::{PublicKey, SecretKey, Signature};
use crate::hashing::{ScalarDigest, SignatureDigest};
use crate::params::Parameters;
use crate::traits::SerializableToArray;

use alloc::boxed::Box;
use alloc::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::{op, U1};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KeyFragProof {
    pub(crate) commitment: CurvePoint,
    signature_for_proxy: Signature,
    signature_for_bob: Signature,
    delegating_key_signed: bool,
    receiving_key_signed: bool,
}

type ParametersSize = <Parameters as SerializableToArray>::Size;
type SignatureSize = <Signature as SerializableToArray>::Size;
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
        let (signature_for_proxy, rest) = Signature::take(rest)?;
        let (signature_for_bob, rest) = Signature::take(rest)?;
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
        params: &Parameters,
        kfrag_id: &CurveScalar,
        kfrag_key: &CurveScalar,
        kfrag_precursor: &CurvePoint,
        signing_sk: &SecretKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let commitment = &params.u * kfrag_key;

        let signature_for_bob = SignatureDigest::new()
            .chain_scalar(kfrag_id)
            .chain_pubkey(delegating_pk)
            .chain_pubkey(receiving_pk)
            .chain_point(&commitment)
            .chain_point(kfrag_precursor)
            .sign(signing_sk);

        let mut digest_for_proxy = SignatureDigest::new()
            .chain_scalar(kfrag_id)
            .chain_point(&commitment)
            .chain_point(kfrag_precursor)
            .chain_bool(sign_delegating_key)
            .chain_bool(sign_receiving_key);

        if sign_delegating_key {
            digest_for_proxy = digest_for_proxy.chain_pubkey(delegating_pk);
        }

        if sign_receiving_key {
            digest_for_proxy = digest_for_proxy.chain_pubkey(receiving_pk);
        }

        let signature_for_proxy = digest_for_proxy.sign(&signing_sk);

        Self {
            commitment,
            signature_for_proxy,
            signature_for_bob,
            delegating_key_signed: sign_delegating_key,
            receiving_key_signed: sign_receiving_key,
        }
    }

    pub(crate) fn signature_for_bob(&self) -> Signature {
        self.signature_for_bob.clone()
    }
}

/// A fragment of the encrypting party's key used to create a [`CapsuleFrag`](`crate::CapsuleFrag`).
#[derive(Clone, Debug, PartialEq)]
pub struct KeyFrag {
    params: Parameters,
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
        let (params, rest) = Parameters::take(*arr)?;
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
            &factory.signing_sk,
            &factory.delegating_pk,
            &factory.receiving_pk,
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

    /// Verifies the integrity of the key fragment, given the signing key,
    /// and (optionally) the encrypting party's and decrypting party's keys.
    ///
    /// If [`generate_kfrags()`](`crate::generate_kfrags()`) was called with `true`
    /// for `sign_delegating_key` or `sign_receiving_key`, and the respective key
    /// is not provided, the verification fails.
    pub fn verify(
        &self,
        signing_pk: &PublicKey,
        delegating_pk: Option<&PublicKey>,
        receiving_pk: Option<&PublicKey>,
    ) -> bool {
        if self.proof.delegating_key_signed && delegating_pk.is_none() {
            return false;
        }

        if self.proof.receiving_key_signed && receiving_pk.is_none() {
            return false;
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
            // `delegating_pk` is guaranteed to be Some here.
            digest = digest.chain_pubkey(&delegating_pk.unwrap());
        }
        if self.proof.receiving_key_signed {
            // `receiving_pk` is guaranteed to be Some here.
            digest = digest.chain_pubkey(&receiving_pk.unwrap());
        }
        let valid_kfrag_signature = digest.verify(&signing_pk, &self.proof.signature_for_proxy);

        correct_commitment & valid_kfrag_signature
    }
}

struct KeyFragFactory {
    signing_sk: SecretKey,
    precursor: CurvePoint,
    bob_pubkey_point: CurvePoint,
    dh_point: CurvePoint,
    params: Parameters,
    delegating_pk: PublicKey,
    receiving_pk: PublicKey,
    coefficients: Box<[CurveScalar]>,
}

impl KeyFragFactory {
    pub fn new(
        params: &Parameters,
        delegating_sk: &SecretKey,
        receiving_pk: &PublicKey,
        signing_sk: &SecretKey,
        threshold: usize,
    ) -> Self {
        let g = CurvePoint::generator();

        let delegating_pk = PublicKey::from_secret_key(delegating_sk);

        let bob_pubkey_point = receiving_pk.to_point();

        let (d, precursor, dh_point) = loop {
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

            // TODO: at the moment we cannot statically ensure `d` is a `NonZeroScalar`.
            if !d.is_zero() {
                break (d, precursor, dh_point);
            }
        };

        // Coefficients of the generating polynomial
        // `invert()` is guaranteed not to panic because `d` is nonzero.
        let coefficient0 = &delegating_sk.to_secret_scalar() * &(d.invert().unwrap());

        let mut coefficients = Vec::<CurveScalar>::with_capacity(threshold);
        coefficients.push(coefficient0);
        for _i in 1..threshold {
            coefficients.push(CurveScalar::random_nonzero());
        }

        Self {
            signing_sk: signing_sk.clone(),
            precursor,
            bob_pubkey_point,
            dh_point,
            params: *params,
            delegating_pk,
            receiving_pk: *receiving_pk,
            coefficients: coefficients.into_boxed_slice(),
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

/// Creates `num_kfrags` fragments of `delegating_sk`,
/// which will be possible to reencrypt to allow the creator of `receiving_pk`
/// decrypt the ciphertext encrypted with `delegating_sk`.
///
/// `threshold` sets the number of fragments necessary for decryption
/// (that is, fragments created with `threshold > num_frags` will be useless).
///
/// `signing_sk` is used to sign the resulting [`KeyFrag`] and
/// reencrypted [`CapsuleFrag`](`crate::CapsuleFrag`) objects, which can be later verified
/// by the associated public key.
///
/// If `sign_delegating_key` or `sign_receiving_key` are `true`,
/// the reencrypting party will be able to verify that a [`KeyFrag`]
/// corresponds to given delegating or receiving public keys
/// by supplying them to [`KeyFrag::verify()`].
///
/// Returns a boxed slice of `num_kfrags` KeyFrags
#[allow(clippy::too_many_arguments)]
pub fn generate_kfrags(
    params: &Parameters,
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signing_sk: &SecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Box<[KeyFrag]> {
    let base = KeyFragFactory::new(params, delegating_sk, receiving_pk, signing_sk, threshold);

    let mut result = Vec::<KeyFrag>::new();
    for _ in 0..num_kfrags {
        result.push(KeyFrag::new(&base, sign_delegating_key, sign_receiving_key));
    }

    result.into_boxed_slice()
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    use super::{generate_kfrags, KeyFrag};
    use crate::{Parameters, PublicKey, SecretKey, SerializableToArray};

    fn prepare_kfrags(sign_delegating_key: bool, sign_receiving_key: bool) -> (PublicKey, PublicKey, PublicKey, Box<[KeyFrag]>) {
        let params = Parameters::new();

        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let signing_pk = PublicKey::from_secret_key(&signing_sk);

        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        let kfrags = generate_kfrags(
            &params,
            &delegating_sk,
            &receiving_pk,
            &signing_sk,
            2,
            3,
            sign_delegating_key,
            sign_receiving_key,
        );

        (delegating_pk, receiving_pk, signing_pk, kfrags)
    }

    #[test]
    fn test_serialize() {
        let (_, _, _, kfrags) = prepare_kfrags(true, true);
        let kfrag_arr = kfrags[0].to_array();
        let kfrag_back = KeyFrag::from_array(&kfrag_arr).unwrap();
        assert_eq!(kfrags[0], kfrag_back);
    }

    #[test]
    fn test_verify() {
        let (delegating_pk, receiving_pk, signing_pk, kfrags) = prepare_kfrags(true, true);
        assert!(kfrags[0].verify(&signing_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(!kfrags[0].verify(&signing_pk, None, Some(&receiving_pk)));

        let (delegating_pk, receiving_pk, signing_pk, kfrags) = prepare_kfrags(false, true);
        assert!(kfrags[0].verify(&signing_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(kfrags[0].verify(&signing_pk, None, Some(&receiving_pk)));
        assert!(!kfrags[0].verify(&signing_pk, Some(&delegating_pk), None));

        let (delegating_pk, receiving_pk, signing_pk, kfrags) = prepare_kfrags(true, false);
        assert!(kfrags[0].verify(&signing_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(!kfrags[0].verify(&signing_pk, None, Some(&receiving_pk)));
        assert!(kfrags[0].verify(&signing_pk, Some(&delegating_pk), None));

        let (delegating_pk, receiving_pk, signing_pk, kfrags) = prepare_kfrags(false, false);
        assert!(kfrags[0].verify(&signing_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(kfrags[0].verify(&signing_pk, None, None));
        assert!(!kfrags[0].verify(&delegating_pk, None, None));
    }
}
