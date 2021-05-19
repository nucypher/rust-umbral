use crate::curve::{CurvePoint, CurveScalar};
use crate::hashing_ds::{hash_to_polynomial_arg, hash_to_shared_secret, kfrag_signature_message};
use crate::keys::{PublicKey, SecretKey, Signature, Signer};
use crate::params::Parameters;
use crate::traits::{
    DeserializableFromArray, DeserializationError, RepresentableAsArray, SerializableToArray,
};

use alloc::boxed::Box;
use alloc::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use rand_core::{OsRng, RngCore};
use typenum::{op, U32};

#[allow(clippy::upper_case_acronyms)]
type KeyFragIDSize = U32;

#[allow(clippy::upper_case_acronyms)]
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

impl RepresentableAsArray for KeyFragID {
    type Size = KeyFragIDSize;
}

impl SerializableToArray for KeyFragID {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0
    }
}

impl DeserializableFromArray for KeyFragID {
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

type SignatureSize = <Signature as RepresentableAsArray>::Size;
type ScalarSize = <CurveScalar as RepresentableAsArray>::Size;
type PointSize = <CurvePoint as RepresentableAsArray>::Size;
type BoolSize = <bool as RepresentableAsArray>::Size;
type KeyFragProofSize = op!(PointSize + SignatureSize + SignatureSize + BoolSize + BoolSize);

impl RepresentableAsArray for KeyFragProof {
    type Size = KeyFragProofSize;
}

impl SerializableToArray for KeyFragProof {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.commitment
            .to_array()
            .concat(self.signature_for_proxy.to_array())
            .concat(self.signature_for_receiver.to_array())
            .concat(self.delegating_key_signed.to_array())
            .concat(self.receiving_key_signed.to_array())
    }
}

impl DeserializableFromArray for KeyFragProof {
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

        let signature_for_receiver = base.signer.sign(
            kfrag_signature_message(
                &kfrag_id,
                &commitment,
                &base.precursor,
                maybe_delegating_pk,
                maybe_receiving_pk,
            )
            .as_ref(),
        );

        let signature_for_proxy = base.signer.sign(
            kfrag_signature_message(
                &kfrag_id,
                &commitment,
                &base.precursor,
                none_unless(maybe_delegating_pk, sign_delegating_key),
                none_unless(maybe_receiving_pk, sign_receiving_key),
            )
            .as_ref(),
        );

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

impl RepresentableAsArray for KeyFrag {
    type Size = op!(ScalarSize + ScalarSize + PointSize + KeyFragProofSize);
}

impl SerializableToArray for KeyFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.id
            .to_array()
            .concat(self.key.to_array())
            .concat(self.precursor.to_array())
            .concat(self.proof.to_array())
    }
}

impl DeserializableFromArray for KeyFrag {
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

/// Possible errors that can be returned by [`KeyFrag::verify`].
#[derive(Debug, PartialEq)]
pub enum KeyFragVerificationError {
    /// Inconsistent internal state leading to commitment verification failure.
    IncorrectCommitment,
    /// A delegating key was included in the signature when [`KeyFrag`] was created,
    /// but no delegating key was provided during verification.
    DelegatingKeyNotProvided,
    /// A receiving key was included in the signature when [`KeyFrag`] was created,
    /// but no receiving key was provided during verification.
    ReceivingKeyNotProvided,
    /// Inconsistent internal state leading to signature verification failure.
    IncorrectSignature,
}

impl KeyFrag {
    fn from_base(base: &KeyFragBase, sign_delegating_key: bool, sign_receiving_key: bool) -> Self {
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
    ) -> Result<VerifiedKeyFrag, KeyFragVerificationError> {
        let u = self.params.u;

        let kfrag_id = self.id;
        let key = self.key;
        let commitment = self.proof.commitment;
        let precursor = self.precursor;

        // We check that the commitment is well-formed
        if commitment != &u * &key {
            return Err(KeyFragVerificationError::IncorrectCommitment);
        }

        // A shortcut, perhaps not necessary

        if maybe_delegating_pk.is_none() && self.proof.delegating_key_signed {
            return Err(KeyFragVerificationError::DelegatingKeyNotProvided);
        }

        if maybe_receiving_pk.is_none() && self.proof.receiving_key_signed {
            return Err(KeyFragVerificationError::ReceivingKeyNotProvided);
        }

        // Check the signature

        if !self.proof.signature_for_proxy.verify(
            verifying_pk,
            kfrag_signature_message(
                &kfrag_id,
                &commitment,
                &precursor,
                none_unless(maybe_delegating_pk, self.proof.delegating_key_signed),
                none_unless(maybe_receiving_pk, self.proof.receiving_key_signed),
            )
            .as_ref(),
        ) {
            return Err(KeyFragVerificationError::IncorrectSignature);
        }

        Ok(VerifiedKeyFrag {
            kfrag: self.clone(),
        })
    }
}

/// Verified key fragment, good for reencryption.
/// Can be serialized, but cannot be deserialized directly.
/// It can only be obtained from [`KeyFrag::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedKeyFrag {
    pub(crate) kfrag: KeyFrag,
}

impl RepresentableAsArray for VerifiedKeyFrag {
    type Size = <KeyFrag as RepresentableAsArray>::Size;
}

impl SerializableToArray for VerifiedKeyFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.kfrag.to_array()
    }
}

impl VerifiedKeyFrag {
    pub(crate) fn from_base(
        base: &KeyFragBase,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        Self {
            kfrag: KeyFrag::from_base(base, sign_delegating_key, sign_receiving_key),
        }
    }
}

pub(crate) struct KeyFragBase {
    signer: Signer,
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
        signer: &Signer,
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
            signer: signer.clone(),
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

    use super::{KeyFrag, KeyFragBase, KeyFragVerificationError, VerifiedKeyFrag};
    use crate::{DeserializableFromArray, PublicKey, SecretKey, SerializableToArray, Signer};

    fn prepare_kfrags(
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> (PublicKey, PublicKey, PublicKey, Box<[VerifiedKeyFrag]>) {
        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let signer = Signer::new(&signing_sk);
        let verifying_pk = PublicKey::from_secret_key(&signing_sk);

        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        let base = KeyFragBase::new(&delegating_sk, &receiving_pk, &signer, 2);
        let vkfrags = [
            VerifiedKeyFrag::from_base(&base, sign_delegating_key, sign_receiving_key),
            VerifiedKeyFrag::from_base(&base, sign_delegating_key, sign_receiving_key),
            VerifiedKeyFrag::from_base(&base, sign_delegating_key, sign_receiving_key),
        ];

        (delegating_pk, receiving_pk, verifying_pk, Box::new(vkfrags))
    }

    #[test]
    fn test_verify() {
        for sign_dk in [false, true].iter().copied() {
            for sign_rk in [false, true].iter().copied() {
                let (delegating_pk, receiving_pk, verifying_pk, vkfrags) =
                    prepare_kfrags(sign_dk, sign_rk);

                let kfrag_arr = vkfrags[0].to_array();
                let kfrag = KeyFrag::from_array(&kfrag_arr).unwrap();

                // Check that the kfrag serializes to the same thing as the verified kfrag
                assert_eq!(kfrag.to_array(), kfrag_arr);

                for supply_dk in [false, true].iter().copied() {
                    for supply_rk in [false, true].iter().copied() {
                        let maybe_dk = if supply_dk {
                            Some(&delegating_pk)
                        } else {
                            None
                        };
                        let maybe_rk = if supply_rk { Some(&receiving_pk) } else { None };
                        let res = kfrag.verify(&verifying_pk, maybe_dk, maybe_rk);

                        let sufficient_dk = !sign_dk || (supply_dk == sign_dk);
                        let sufficient_rk = !sign_rk || (supply_rk == sign_rk);

                        if sufficient_dk && sufficient_rk {
                            assert!(res.is_ok());
                            assert_eq!(res.unwrap().kfrag, kfrag);
                        } else if !sufficient_dk {
                            assert_eq!(
                                res,
                                Err(KeyFragVerificationError::DelegatingKeyNotProvided)
                            );
                        } else if !sufficient_rk {
                            assert_eq!(res, Err(KeyFragVerificationError::ReceivingKeyNotProvided));
                        }
                    }
                }
            }
        }
    }
}
