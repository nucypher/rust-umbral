use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use typenum::{op, U32};

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::curve::{CurvePoint, CurveScalar, NonZeroCurveScalar};
use crate::hashing_ds::{hash_to_polynomial_arg, hash_to_shared_secret, kfrag_signature_message};
use crate::keys::{PublicKey, SecretKey, Signature, Signer};
use crate::params::Parameters;
use crate::secret_box::SecretBox;
use crate::traits::{
    fmt_public, ConstructionError, DeserializableFromArray, DeserializationError, HasTypeName,
    RepresentableAsArray, SerializableToArray,
};

#[cfg(feature = "serde-support")]
use crate::serde::{serde_deserialize, serde_serialize, Representation};

#[allow(clippy::upper_case_acronyms)]
type KeyFragIDSize = U32;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct KeyFragID(GenericArray<u8, KeyFragIDSize>);

impl KeyFragID {
    fn random(rng: &mut impl RngCore) -> Self {
        let mut bytes = GenericArray::<u8, KeyFragIDSize>::default();
        rng.fill_bytes(&mut bytes);
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
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
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
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
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
        rng: &mut (impl CryptoRng + RngCore),
        base: &KeyFragBase,
        kfrag_id: &KeyFragID,
        kfrag_key: &CurveScalar,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let commitment = &base.params.u * kfrag_key;

        let maybe_delegating_pk = Some(&base.delegating_pk);
        let maybe_receiving_pk = Some(&base.receiving_pk);

        let signature_for_receiver = base.signer.sign_with_rng(
            rng,
            kfrag_signature_message(
                kfrag_id,
                &commitment,
                &base.precursor,
                maybe_delegating_pk,
                maybe_receiving_pk,
            )
            .as_ref(),
        );

        let signature_for_proxy = base.signer.sign_with_rng(
            rng,
            kfrag_signature_message(
                kfrag_id,
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
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
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

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for KeyFrag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for KeyFrag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl HasTypeName for KeyFrag {
    fn type_name() -> &'static str {
        "KeyFrag"
    }
}

impl fmt::Display for KeyFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
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

impl fmt::Display for KeyFragVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectCommitment => write!(f, "Invalid kfrag commitment"),
            Self::DelegatingKeyNotProvided => write!(f, "A signature of a delegating key was included in this kfrag but the key is not provided"),
            Self::ReceivingKeyNotProvided => write!(f, "A signature of a receiving key was included in this kfrag, but the key is not provided"),
            Self::IncorrectSignature => write!(f, "Failed to verify the kfrag signature"),
        }
    }
}

impl KeyFrag {
    fn from_base(
        rng: &mut (impl CryptoRng + RngCore),
        base: &KeyFragBase,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        let kfrag_id = KeyFragID::random(rng);

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
            rng,
            base,
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

    /// Explicitly skips verification.
    /// Useful in cases when the verifying keys are impossible to obtain independently.
    ///
    /// **Warning:** make sure you considered the implications of not enforcing verification.
    pub fn skip_verification(self) -> VerifiedKeyFrag {
        VerifiedKeyFrag { kfrag: self }
    }
}

/// Verified key fragment, good for reencryption.
/// Can be serialized, but cannot be deserialized directly.
/// It can only be obtained from [`KeyFrag::verify`] or [`KeyFrag::skip_verification`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedKeyFrag {
    kfrag: KeyFrag,
}

impl RepresentableAsArray for VerifiedKeyFrag {
    type Size = <KeyFrag as RepresentableAsArray>::Size;
}

impl SerializableToArray for VerifiedKeyFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.kfrag.to_array()
    }
}

impl HasTypeName for VerifiedKeyFrag {
    fn type_name() -> &'static str {
        "VerifiedKeyFrag"
    }
}

impl fmt::Display for VerifiedKeyFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

impl VerifiedKeyFrag {
    pub(crate) fn from_base(
        rng: &mut (impl CryptoRng + RngCore),
        base: &KeyFragBase,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> Self {
        Self {
            kfrag: KeyFrag::from_base(rng, base, sign_delegating_key, sign_receiving_key),
        }
    }

    /// Restores a verified keyfrag directly from serialized bytes,
    /// skipping [`KeyFrag::verify`] call.
    ///
    /// Intended for internal storage;
    /// make sure that the bytes come from a trusted source.
    pub fn from_verified_bytes(data: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        KeyFrag::from_bytes(data).map(|kfrag| Self { kfrag })
    }

    /// Clears the verification status from the keyfrag.
    /// Useful for the cases where it needs to be put in the protocol structure
    /// containing [`KeyFrag`] types (since those are the ones
    /// that can be serialized/deserialized freely).
    pub fn to_unverified(&self) -> KeyFrag {
        self.kfrag.clone()
    }
}

pub(crate) struct KeyFragBase {
    signer: Signer,
    precursor: CurvePoint,
    dh_point: CurvePoint,
    params: Parameters,
    delegating_pk: PublicKey,
    receiving_pk: PublicKey,
    coefficients: Box<[SecretBox<NonZeroCurveScalar>]>,
}

impl KeyFragBase {
    pub fn new(
        rng: &mut (impl CryptoRng + RngCore),
        delegating_sk: &SecretKey,
        receiving_pk: &PublicKey,
        signer: &Signer,
        threshold: usize,
    ) -> Self {
        let g = CurvePoint::generator();
        let params = Parameters::new();

        let delegating_pk = delegating_sk.public_key();

        let receiving_pk_point = receiving_pk.to_point();

        // The precursor point is used as an ephemeral public key in a DH key exchange,
        // and the resulting shared secret 'dh_point' is used to derive other secret values
        let private_precursor = SecretBox::new(NonZeroCurveScalar::random(rng));
        let precursor = &g * private_precursor.as_secret();

        let dh_point = &receiving_pk_point * private_precursor.as_secret();

        // Secret value 'd' allows to make Umbral non-interactive
        let d = hash_to_shared_secret(&precursor, &receiving_pk_point, &dh_point);

        // Coefficients of the generating polynomial
        let coefficient0 =
            SecretBox::new(delegating_sk.to_secret_scalar().as_secret() * &(d.invert()));

        let mut coefficients = Vec::<SecretBox<NonZeroCurveScalar>>::with_capacity(threshold);
        coefficients.push(coefficient0);
        for _i in 1..threshold {
            coefficients.push(SecretBox::new(NonZeroCurveScalar::random(rng)));
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
fn poly_eval(coeffs: &[SecretBox<NonZeroCurveScalar>], x: &NonZeroCurveScalar) -> CurveScalar {
    let mut result: SecretBox<CurveScalar> =
        SecretBox::new(coeffs[coeffs.len() - 1].as_secret().into());
    for i in (0..coeffs.len() - 1).rev() {
        // Keeping the intermediate results zeroized as well
        let temp = SecretBox::new(result.as_secret() * x);
        *result.as_mut_secret() = temp.as_secret() + coeffs[i].as_secret();
    }
    // This is not a secret anymore
    *result.as_secret()
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    use rand_core::OsRng;

    use super::{KeyFrag, KeyFragBase, KeyFragVerificationError, VerifiedKeyFrag};

    use crate::{DeserializableFromArray, PublicKey, SecretKey, SerializableToArray, Signer};

    #[cfg(feature = "serde-support")]
    use crate::serde::tests::{check_deserialization, check_serialization};

    #[cfg(feature = "serde-support")]
    use crate::serde::Representation;

    fn prepare_kfrags(
        sign_delegating_key: bool,
        sign_receiving_key: bool,
    ) -> (PublicKey, PublicKey, PublicKey, Box<[VerifiedKeyFrag]>) {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let signing_sk = SecretKey::random();
        let signer = Signer::new(&signing_sk);
        let verifying_pk = signing_sk.public_key();

        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();

        let base = KeyFragBase::new(&mut OsRng, &delegating_sk, &receiving_pk, &signer, 2);
        let vkfrags = [
            VerifiedKeyFrag::from_base(&mut OsRng, &base, sign_delegating_key, sign_receiving_key),
            VerifiedKeyFrag::from_base(&mut OsRng, &base, sign_delegating_key, sign_receiving_key),
            VerifiedKeyFrag::from_base(&mut OsRng, &base, sign_delegating_key, sign_receiving_key),
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

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serde_serialization() {
        let (_delegating_pk, _receiving_pk, _verifying_pk, verified_kfrags) =
            prepare_kfrags(true, true);

        let vkfrag = verified_kfrags[0].clone();
        let kfrag = KeyFrag::from_array(&vkfrag.to_array()).unwrap();

        check_serialization(&kfrag, Representation::Base64);
        check_deserialization(&kfrag);
    }
}
