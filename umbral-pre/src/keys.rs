use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use core::cmp::Ordering;
use core::fmt;

use generic_array::{
    typenum::{Unsigned, U32, U64},
    GenericArray,
};
use k256::{
    ecdsa::{
        signature::{DigestVerifier, RandomizedDigestSigner},
        RecoveryId, Signature as BackendSignature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{FieldBytes, PublicKey as BackendPublicKey, SecretKey as BackendSecretKey},
};
use rand_core::{CryptoRng, RngCore};
use sha2::digest::{Digest, FixedOutput};
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "default-rng")]
use rand_core::OsRng;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::curve::{CompressedPointSize, CurvePoint, CurveType, NonZeroCurveScalar, ScalarSize};
use crate::dem::kdf;
use crate::hashing::{BackendDigest, Hash, ScalarDigest};
use crate::secret_box::SecretBox;
use crate::traits::{fmt_public, fmt_secret, SizeMismatchError};

#[cfg(feature = "serde-support")]
use crate::serde_bytes::{
    deserialize_with_encoding, serialize_with_encoding, Encoding, TryFromBytes,
};

/// ECDSA signature object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(BackendSignature);

impl Signature {
    /// Returns the signature serialized as concatenated `r` and `s`
    /// in big endian order (32+32 bytes).
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        AsRef::<[u8]>::as_ref(&self.0.to_bytes()).into()
    }

    /// Restores the signature from concatenated `r` and `s`
    /// in big endian order (32+32 bytes).
    pub fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!(
                "Invalid length for a serialized signature: {}, expected 64",
                bytes.len()
            ));
        }

        let r = FieldBytes::<CurveType>::from_slice(&bytes[0..32]);
        let s = FieldBytes::<CurveType>::from_slice(&bytes[32..64]);
        BackendSignature::from_scalars(*r, *s)
            .map(Self)
            .map_err(|err| format!("Internal backend error: {err}"))
    }

    /// Returns the signature serialized in ASN.1 DER format.
    pub fn to_der_bytes(&self) -> Box<[u8]> {
        self.0.to_der().as_bytes().into()
    }

    /// Restores the signature from a bytestring in ASN.1 DER format.
    pub fn try_from_der_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Note that it will not normalize `s` automatically,
        // and if it is not normalized, verification will fail.
        BackendSignature::from_der(bytes)
            .map(Self)
            .map_err(|err| format!("Internal backend error: {err}"))
    }

    /// Verifies that the given message was signed with the secret counterpart of the given key.
    /// The message is hashed internally.
    pub fn verify(&self, verifying_pk: &PublicKey, message: &[u8]) -> bool {
        verifying_pk.verify_digest(digest_for_signing(message), self)
    }

    pub(crate) fn get_recovery_id(
        &self,
        verifying_pk: &PublicKey,
        message: &[u8],
    ) -> Option<RecoveryId> {
        let digest = digest_for_signing(message);
        RecoveryId::trial_recovery_from_digest(&verifying_pk.0.into(), digest, &self.0).ok()
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_with_encoding(&self.to_der_bytes(), serializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl TryFromBytes for Signature {
    type Error = String;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_der_bytes(bytes)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public("Signature", &self.to_der_bytes(), f)
    }
}

/// A signature with the recovery byte attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableSignature {
    signature: Signature,
    recovery_id: RecoveryId,
}

impl RecoverableSignature {
    /// Create the recoverable signature from the signature proper and the recovery flag.
    #[cfg(test)]
    pub(crate) fn from_normalized(signature: Signature, is_y_odd: bool) -> Self {
        Self {
            signature,
            // TODO: currently `RecoveryId.is_x_reduced` is ignored during recovery
            // (see `VerifyingKey::recover_from_prehash()`), so we set it to `false`.
            // Make sure this parameter is handled properly if this method is made public.
            recovery_id: RecoveryId::new(is_y_odd, false),
        }
    }

    /// Returns the signature serialized as concatenated `r`, `s`, and `v`
    /// in big endian order (32+32+1 bytes).
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        [
            AsRef::<[u8]>::as_ref(&self.signature.to_be_bytes()),
            &[self.recovery_id.to_byte()],
        ]
        .concat()
        .into()
    }

    /// Restores the signature from concatenated `r`, `s`, and `v`
    /// in big endian order (32+32+1 bytes).
    pub fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        // The signature size is exported from `ecdsa` crate (as `SignatureSize` type),
        // and I don't really want to add it to dependencies just because of this constant.
        const SIGNATURE_SIZE: usize = 64;

        if bytes.len() != SIGNATURE_SIZE + 1 {
            return Err("Invalid size of a recoverable signature".into());
        }

        let signature = Signature::try_from_be_bytes(&bytes[0..SIGNATURE_SIZE])?;
        let recovery_id = RecoveryId::from_byte(bytes[SIGNATURE_SIZE])
            .ok_or_else(|| "Invalid recovery byte".to_string())?;

        Ok(RecoverableSignature {
            signature,
            recovery_id,
        })
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for RecoverableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_with_encoding(&self.to_be_bytes(), serializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for RecoverableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl TryFromBytes for RecoverableSignature {
    type Error = String;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_be_bytes(bytes)
    }
}

impl fmt::Display for RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public("RecoverableSignature", &self.to_be_bytes(), f)
    }
}

/// A secret key.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretKey(BackendSecretKey<CurveType>);

impl SecretKey {
    fn new(sk: BackendSecretKey<CurveType>) -> Self {
        Self(sk)
    }

    /// Creates a secret key using the given RNG.
    pub fn random_with_rng(rng: impl CryptoRng + RngCore) -> Self {
        Self::new(BackendSecretKey::<CurveType>::random(rng))
    }

    /// Creates a secret key using the default RNG.
    #[cfg(feature = "default-rng")]
    #[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
    pub fn random() -> Self {
        Self::random_with_rng(&mut OsRng)
    }

    /// Returns a public key corresponding to this secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    fn from_nonzero_scalar(scalar: SecretBox<NonZeroCurveScalar>) -> Self {
        let backend_scalar_ref = scalar.as_secret().as_backend_scalar();
        Self::new(BackendSecretKey::<CurveType>::from(backend_scalar_ref))
    }

    /// Returns a reference to the underlying scalar of the secret key.
    pub(crate) fn to_secret_scalar(&self) -> SecretBox<NonZeroCurveScalar> {
        let backend_scalar = SecretBox::new(self.0.to_nonzero_scalar());
        SecretBox::new(NonZeroCurveScalar::from_backend_scalar(
            *backend_scalar.as_secret(),
        ))
    }

    /// Serializes the secret key as a scalar in the big-endian representation.
    pub fn to_be_bytes(&self) -> SecretBox<GenericArray<u8, ScalarSize>> {
        SecretBox::new(self.0.to_be_bytes())
    }

    /// Deserializes the secret key from a scalar in the big-endian representation.
    pub fn try_from_be_bytes(
        bytes: &SecretBox<GenericArray<u8, ScalarSize>>,
    ) -> Result<Self, String> {
        BackendSecretKey::<CurveType>::from_be_bytes(bytes.as_secret().as_slice())
            .map(Self::new)
            .map_err(|err| format!("{err}"))
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_secret("SecretKey", f)
    }
}

pub(crate) fn digest_for_signing(message: &[u8]) -> BackendDigest {
    Hash::new().chain_bytes(message).digest()
}

/// An object used to sign messages.
/// For security reasons cannot be serialized.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Signer(SigningKey);

impl Signer {
    /// Creates a new signer out of a secret key.
    pub fn new(sk: SecretKey) -> Self {
        Self(SigningKey::from(sk.0.clone()))
    }

    /// Signs the given message using the given RNG.
    pub fn sign_with_rng(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8]) -> Signature {
        let digest = digest_for_signing(message);
        Signature(self.0.sign_digest_with_rng(rng, digest))
    }

    /// Signs the given message using the default RNG.
    #[cfg(feature = "default-rng")]
    #[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_with_rng(&mut OsRng, message)
    }

    /// Returns the public key that can be used to verify the signatures produced by this signer.
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().into())
    }
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_secret("Signer", f)
    }
}

/// A public key.
///
/// Create using [`SecretKey::public_key`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(BackendPublicKey<CurveType>);

impl PublicKey {
    /// Returns the underlying curve point of the public key.
    pub(crate) fn to_point(self) -> CurvePoint {
        CurvePoint::from_backend_point(&self.0.to_projective())
    }

    /// Verifies the signature.
    pub(crate) fn verify_digest(
        &self,
        digest: impl Digest<OutputSize = U32> + FixedOutput,
        signature: &Signature,
    ) -> bool {
        let verifier = VerifyingKey::from(&self.0);
        verifier.verify_digest(digest, &signature.0).is_ok()
    }

    /// Recovers the public key from a prehashed message
    /// and the corresponding recoverable signature.
    pub fn recover_from_prehash(
        prehash: &[u8],
        signature: &RecoverableSignature,
    ) -> Result<Self, String> {
        let vkey = VerifyingKey::recover_from_prehash(
            prehash,
            &signature.signature.0,
            signature.recovery_id,
        )
        .map_err(|err| format!("Internal backend error: {err}"))?;
        Ok(Self(vkey.into()))
    }

    /// Restores the public key from a compressed curve point.
    pub fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        let cp = CurvePoint::try_from_compressed_bytes(bytes)?;
        BackendPublicKey::<CurveType>::try_from(cp.as_backend_point())
            .map(Self)
            .map_err(|_| "Cannot instantiate a public key from the given curve point".into())
    }

    /// Retunrs the serialized pubic key as the compressed curve point.
    pub fn to_compressed_bytes(self) -> Box<[u8]> {
        let arr: GenericArray<u8, CompressedPointSize> = self.to_point().to_compressed_array();
        let slice: &[u8] = arr.as_ref();
        slice.into()
    }

    /// Retunrs the serialized pubic key as the uncompressed curve point.
    pub fn to_uncompressed_bytes(self) -> Box<[u8]> {
        self.to_point().to_uncompressed_bytes()
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_with_encoding(&self.to_compressed_bytes(), serializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl TryFromBytes for PublicKey {
    type Error = String;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_compressed_bytes(bytes)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public("PublicKey", &self.to_compressed_bytes(), f)
    }
}

type SecretKeyFactorySeedSize = U32; // the size of the seed material for key derivation
type SecretKeyFactoryDerivedSize = U64; // the size of the derived key (before hashing to scalar)
type SecretKeyFactorySeed = GenericArray<u8, SecretKeyFactorySeedSize>;

/// This class handles keyring material for Umbral, by allowing deterministic
/// derivation of `SecretKey` objects based on labels.
#[derive(Clone, ZeroizeOnDrop, PartialEq)]
pub struct SecretKeyFactory(SecretBox<SecretKeyFactorySeed>);

impl SecretKeyFactory {
    /// Creates a secret key factory using the given RNG.
    pub fn random_with_rng(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut bytes = SecretBox::new(SecretKeyFactorySeed::default());
        rng.fill_bytes(bytes.as_mut_secret());
        Self(bytes)
    }

    /// Creates a secret key factory using the default RNG.
    #[cfg(feature = "default-rng")]
    #[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
    pub fn random() -> Self {
        Self::random_with_rng(&mut OsRng)
    }

    /// Returns the seed size required by
    /// [`from_secure_randomness`](`SecretKeyFactory::from_secure_randomness`).
    pub fn seed_size() -> usize {
        SecretKeyFactorySeedSize::to_usize()
    }

    /// Creates a secret key factory using the given random bytes.
    ///
    /// **Warning:** make sure the given seed has been obtained
    /// from a cryptographically secure source of randomness!
    pub fn from_secure_randomness(seed: &[u8]) -> Result<Self, SizeMismatchError> {
        let received_size = seed.len();
        let expected_size = Self::seed_size();
        match received_size.cmp(&expected_size) {
            Ordering::Greater | Ordering::Less => {
                Err(SizeMismatchError::new(received_size, expected_size))
            }
            Ordering::Equal => Ok(Self(SecretBox::new(*SecretKeyFactorySeed::from_slice(
                seed,
            )))),
        }
    }

    /// Creates an untyped bytestring deterministically from the given label.
    /// This can be used externally to seed some kind of a secret key.
    pub fn make_secret(
        &self,
        label: &[u8],
    ) -> SecretBox<GenericArray<u8, SecretKeyFactoryDerivedSize>> {
        let prefix = b"SECRET_DERIVATION/";
        let info = [prefix, label].concat();
        kdf::<SecretKeyFactoryDerivedSize>(self.0.as_secret(), None, Some(&info))
    }

    /// Creates a `SecretKey` deterministically from the given label.
    pub fn make_key(&self, label: &[u8]) -> SecretKey {
        let prefix = b"KEY_DERIVATION/";
        let info = [prefix, label].concat();
        let key = kdf::<SecretKeyFactoryDerivedSize>(self.0.as_secret(), None, Some(&info));
        let nz_scalar = SecretBox::new(
            ScalarDigest::new_with_dst(&info)
                .chain_secret_bytes(&key)
                .finalize(),
        );
        SecretKey::from_nonzero_scalar(nz_scalar)
    }

    /// Creates a `SecretKeyFactory` deterministically from the given label.
    pub fn make_factory(&self, label: &[u8]) -> Self {
        let prefix = b"FACTORY_DERIVATION/";
        let info = [prefix, label].concat();
        let derived_seed = kdf::<SecretKeyFactorySeedSize>(self.0.as_secret(), None, Some(&info));
        Self(derived_seed)
    }
}

impl fmt::Display for SecretKeyFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_secret("SecretKeyFactory", f)
    }
}

#[cfg(test)]
mod tests {

    use sha2::digest::Digest;

    use super::{
        digest_for_signing, PublicKey, RecoverableSignature, SecretKey, SecretKeyFactory, Signer,
    };

    #[cfg(feature = "serde-support")]
    use crate::serde_bytes::tests::check_serialization_roundtrip;

    #[test]
    fn test_secret_key_factory() {
        let skf = SecretKeyFactory::random();
        let sk1 = skf.make_key(b"foo");
        let sk2 = skf.make_key(b"foo");
        let sk3 = skf.make_key(b"bar");

        assert!(sk1 == sk2);
        assert!(sk1 != sk3);
    }

    #[test]
    fn test_sign_and_verify() {
        let sk = SecretKey::random();
        let message = b"asdafdahsfdasdfasd";
        let signer = Signer::new(sk.clone());
        let signature = signer.sign(message);

        let pk = sk.public_key();
        let vk = signer.verifying_key();

        assert_eq!(pk, vk);
        assert!(signature.verify(&vk, message));
    }

    #[test]
    fn test_sign_and_recover() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let message: &[u8] = b"asdafdahsfdasdfasd";
        let message_prehashed = digest_for_signing(message).finalize();

        let signer = Signer::new(sk);
        let signature = signer.sign(message);

        for flag in [false, true] {
            let rsig = RecoverableSignature::from_normalized(signature.clone(), flag);
            let pk_rec = PublicKey::recover_from_prehash(&message_prehashed, &rsig).unwrap();

            if pk == pk_rec {
                // Test serialization
                let sig_bytes = signature.to_be_bytes();
                let rsig_bytes = [AsRef::<[u8]>::as_ref(&sig_bytes), &[flag as u8]].concat();
                assert_eq!(&rsig_bytes.clone().into_boxed_slice(), &rsig.to_be_bytes());

                let rsig_deserialized =
                    RecoverableSignature::try_from_be_bytes(&rsig_bytes).unwrap();

                let pk_rec =
                    PublicKey::recover_from_prehash(&message_prehashed, &rsig_deserialized)
                        .unwrap();
                assert_eq!(&pk, &pk_rec);
                assert_eq!(rsig, rsig_deserialized);

                return;
            }
        }

        panic!("Could not find a flag that would recover the original public key");
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serialize_signature() {
        let message = b"asdafdahsfdasdfasd";
        let signer = Signer::new(SecretKey::random());
        let signature = signer.sign(message);

        check_serialization_roundtrip(&signature);
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serialize_recoverable_signature() {
        let message = b"asdafdahsfdasdfasd";
        let signer = Signer::new(SecretKey::random());
        let signature = signer.sign(message);
        let rsig = RecoverableSignature::from_normalized(signature, true);
        check_serialization_roundtrip(&rsig);
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serialize_public_key() {
        let signer = Signer::new(SecretKey::random());
        let pk = signer.verifying_key();

        check_serialization_roundtrip(&pk);
    }
}
