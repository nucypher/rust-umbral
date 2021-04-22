use crate::curve::{CurvePoint, CurveScalar};
use crate::hashing_ds::{hash_to_cfrag_signature, hash_to_polynomial_arg, hash_to_shared_secret};
use crate::keys::{PublicKey, SecretKey, Signature};
use crate::params::Parameters;
use crate::traits::{DeserializationError, SerializableToArray};

use alloc::boxed::Box;
use alloc::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use rand_core::{OsRng, RngCore};
use typenum::{op, U1, U32};

type KeyFragIDSize = U32;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct KeyFragID(GenericArray<u8, KeyFragIDSize>);

impl KeyFragID {
    fn random() -> Self {
        let mut bytes = GenericArray::<u8, KeyFragIDSize>::default();
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl AsRef<[u8]> for KeyFragID {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SerializableToArray for KeyFragID {
    type Size = KeyFragIDSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        Ok(Self(*arr))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KeyFragProof {
    pub(crate) commitment: CurvePoint,
    signature_for_proxy: Signature,
    signature_for_receiver: Signature,
    delegating_key_signed: bool,
    receiving_key_signed: bool,
}

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
            .concat(self.signature_for_receiver.to_array())
            .concat(self.delegating_key_signed.to_array())
            .concat(self.receiving_key_signed.to_array())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        let (commitment, rest) = CurvePoint::take(*arr)?;
        let (signature_for_proxy, rest) = Signature::take(rest)?;
        let (signature_for_receiver, rest) = Signature::take(rest)?;
        let (delegating_key_signed, rest) = bool::take(rest)?;
        let receiving_key_signed = bool::take_last(rest)?;
        Ok(Self {
            commitment,
            signature_for_proxy,
            signature_for_receiver,
            delegating_key_signed,
            receiving_key_signed,
        })
    }
}

fn none_unless<T>(x: Option<T>, predicate: bool) -> Option<T> {
    if predicate {
        x
    } else {
        None
    }
}

impl KeyFragProof {
    fn from_base(
        base: &KeyFragBase,
        kfrag_id: &KeyFragID,
        kfrag_key: &CurveScalar,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let commitment = &base.params.u * kfrag_key;

        let maybe_delegating_pk = Some(&base.delegating_pk);
        let maybe_receiving_pk = Some(&base.receiving_pk);

        let signature_for_receiver = hash_to_cfrag_signature(
            &kfrag_id,
            &commitment,
            &base.precursor,
            maybe_delegating_pk,
            maybe_receiving_pk,
        )
        .sign(&base.signing_sk);

        let signature_for_proxy = hash_to_cfrag_signature(
            &kfrag_id,
            &commitment,
            &base.precursor,
            none_unless(maybe_delegating_pk, sign_delegating_key),
            none_unless(maybe_receiving_pk, sign_receiving_key),
        )
        .sign(&base.signing_sk);

        Self {
            commitment,
            signature_for_proxy,
            signature_for_receiver,
            delegating_key_signed: sign_delegating_key,
            receiving_key_signed: sign_receiving_key,
        }
    }

    pub(crate) fn signature_for_receiver(&self) -> Signature {
        self.signature_for_receiver.clone()
    }
}

/// A fragment of the encrypting party's key used to create a [`CapsuleFrag`](`crate::CapsuleFrag`).
#[derive(Clone, Debug, PartialEq)]
pub struct KeyFrag {
    params: Parameters,
    pub(crate) id: KeyFragID,
    pub(crate) key: CurveScalar,
    pub(crate) precursor: CurvePoint,
    pub(crate) proof: KeyFragProof,
}

type KeyFragSize = op!(ScalarSize + ScalarSize + PointSize + KeyFragProofSize);

impl SerializableToArray for KeyFrag {
    type Size = KeyFragSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.id
            .to_array()
            .concat(self.key.to_array())
            .concat(self.precursor.to_array())
            .concat(self.proof.to_array())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        let params = Parameters::new();
        let (id, rest) = KeyFragID::take(*arr)?;
        let (key, rest) = CurveScalar::take(rest)?;
        let (precursor, rest) = CurvePoint::take(rest)?;
        let proof = KeyFragProof::take_last(rest)?;
        Ok(Self {
            params,
            id,
            key,
            precursor,
            proof,
        })
    }
}

impl KeyFrag {
    pub(crate) fn from_base(
        base: &KeyFragBase,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let kfrag_id = KeyFragID::random();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let share_index = hash_to_polynomial_arg(
            &base.precursor,
            &base.receiving_pk.to_point(),
            &base.dh_point,
            &kfrag_id,
        );

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = poly_eval(&base.coefficients, &share_index);

        let proof = KeyFragProof::from_base(
            &base,
            &kfrag_id,
            &rk,
            sign_delegating_key,
            sign_receiving_key,
        );

        Self {
            params: base.params,
            id: kfrag_id,
            key: rk,
            precursor: base.precursor,
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
        verifying_pk: &PublicKey,
        maybe_delegating_pk: Option<&PublicKey>,
        maybe_receiving_pk: Option<&PublicKey>,
    ) -> bool {
        let u = self.params.u;

        let kfrag_id = self.id;
        let key = self.key;
        let commitment = self.proof.commitment;
        let precursor = self.precursor;

        // We check that the commitment is well-formed
        if commitment != &u * &key {
            return false;
        }

        // A shortcut, perhaps not necessary

        if maybe_delegating_pk.is_none() && self.proof.delegating_key_signed {
            return false;
        }

        if maybe_receiving_pk.is_none() && self.proof.receiving_key_signed {
            return false;
        }

        // Check the signature

        hash_to_cfrag_signature(
            &kfrag_id,
            &commitment,
            &precursor,
            none_unless(maybe_delegating_pk, self.proof.delegating_key_signed),
            none_unless(maybe_receiving_pk, self.proof.receiving_key_signed),
        )
        .verify(&verifying_pk, &self.proof.signature_for_proxy)
    }
}

pub(crate) struct KeyFragBase {
    signing_sk: SecretKey,
    precursor: CurvePoint,
    dh_point: CurvePoint,
    params: Parameters,
    delegating_pk: PublicKey,
    receiving_pk: PublicKey,
    coefficients: Box<[CurveScalar]>,
}

impl KeyFragBase {
    pub fn new(
        delegating_sk: &SecretKey,
        receiving_pk: &PublicKey,
        signing_sk: &SecretKey,
        threshold: usize,
    ) -> Self {
        let g = CurvePoint::generator();
        let params = Parameters::new();

        let delegating_pk = PublicKey::from_secret_key(delegating_sk);

        let receiving_pk_point = receiving_pk.to_point();

        let (d, precursor, dh_point) = loop {
            // The precursor point is used as an ephemeral public key in a DH key exchange,
            // and the resulting shared secret 'dh_point' is used to derive other secret values
            let private_precursor = CurveScalar::random_nonzero();
            let precursor = &g * &private_precursor;

            let dh_point = &receiving_pk_point * &private_precursor;

            // Secret value 'd' allows to make Umbral non-interactive
            let d = hash_to_shared_secret(&precursor, &receiving_pk_point, &dh_point);

            // At the moment we cannot statically ensure `d` is a `NonZeroScalar`,
            // but we need it to be non-zero for the algorithm to work.
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
            dh_point,
            params,
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

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    use super::{KeyFrag, KeyFragBase};
    use crate::{PublicKey, SecretKey, SerializableToArray};

    fn prepare_kfrags(
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> (PublicKey, PublicKey, PublicKey, Box<[KeyFrag]>) {
        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let verifying_pk = PublicKey::from_secret_key(&signing_sk);

        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        let base = KeyFragBase::new(&delegating_sk, &receiving_pk, &signing_sk, 2);
        let kfrags = [
            KeyFrag::from_base(&base, sign_delegating_key, sign_receiving_key),
            KeyFrag::from_base(&base, sign_delegating_key, sign_receiving_key),
            KeyFrag::from_base(&base, sign_delegating_key, sign_receiving_key),
        ];

        (delegating_pk, receiving_pk, verifying_pk, Box::new(kfrags))
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
        let (delegating_pk, receiving_pk, verifying_pk, kfrags) = prepare_kfrags(true, true);
        assert!(kfrags[0].verify(&verifying_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(!kfrags[0].verify(&verifying_pk, None, Some(&receiving_pk)));

        let (delegating_pk, receiving_pk, verifying_pk, kfrags) = prepare_kfrags(false, true);
        assert!(kfrags[0].verify(&verifying_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(kfrags[0].verify(&verifying_pk, None, Some(&receiving_pk)));
        assert!(!kfrags[0].verify(&verifying_pk, Some(&delegating_pk), None));

        let (delegating_pk, receiving_pk, verifying_pk, kfrags) = prepare_kfrags(true, false);
        assert!(kfrags[0].verify(&verifying_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(!kfrags[0].verify(&verifying_pk, None, Some(&receiving_pk)));
        assert!(kfrags[0].verify(&verifying_pk, Some(&delegating_pk), None));

        let (delegating_pk, receiving_pk, verifying_pk, kfrags) = prepare_kfrags(false, false);
        assert!(kfrags[0].verify(&verifying_pk, Some(&delegating_pk), Some(&receiving_pk)));
        assert!(kfrags[0].verify(&verifying_pk, None, None));
        assert!(!kfrags[0].verify(&delegating_pk, None, None));
    }
}
