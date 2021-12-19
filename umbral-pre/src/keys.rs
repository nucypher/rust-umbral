use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use digest::Digest;
use ecdsa::{Signature as BackendSignature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::{PublicKey as BackendPublicKey, SecretKey as BackendSecretKey};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use signature::{DigestVerifier, RandomizedDigestSigner, Signature as SignatureTrait};
use typenum::{Unsigned, U32, U64};

#[cfg(feature = "default-rng")]
use rand_core::OsRng;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::curve::{BackendNonZeroScalar, CurvePoint, CurveScalar, CurveType};
use crate::dem::kdf;
use crate::hashing::{BackendDigest, Hash, ScalarDigest};
use crate::secret_box::{CanBeZeroizedOnDrop, SecretBox};
use crate::traits::{
    fmt_public, fmt_secret, ConstructionError, DeserializableFromArray, HasTypeName,
    RepresentableAsArray, SerializableToArray, SerializableToSecretArray, SizeMismatchError,
};

#[cfg(feature = "serde-support")]
use crate::serde::{serde_deserialize, serde_serialize, Representation};

/// ECDSA signature object.
#[derive(Clone, Debug, PartialEq)]
pub struct Signature(BackendSignature<CurveType>);

impl RepresentableAsArray for Signature {
    type Size = SignatureSize<CurveType>;
}

impl SerializableToArray for Signature {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        *GenericArray::<u8, Self::Size>::from_slice(self.0.as_bytes())
    }
}

impl DeserializableFromArray for Signature {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        // Note that it will not normalize `s` automatically,
        // and if it is not normalized, verification will fail.
        BackendSignature::<CurveType>::from_bytes(arr.as_slice())
            .map(Self)
            .map_err(|_| ConstructionError::new("Signature", "Internal backend error"))
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl Signature {
    /// Verifies that the given message was signed with the secret counterpart of the given key.
    /// The message is hashed internally.
    pub fn verify(&self, verifying_pk: &PublicKey, message: &[u8]) -> bool {
        verifying_pk.verify_digest(digest_for_signing(message), self)
    }
}

impl HasTypeName for Signature {
    fn type_name() -> &'static str {
        "Signature"
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public(self, f)
    }
}

impl CanBeZeroizedOnDrop for BackendSecretKey<CurveType> {
    fn ensure_zeroized_on_drop(&mut self) {
        // BackendSecretKey is zeroized on drop, nothing to do
    }
}

/// A secret key.
#[derive(Clone)]
pub struct SecretKey(SecretBox<BackendSecretKey<CurveType>>);

impl SecretKey {
    fn new(sk: BackendSecretKey<CurveType>) -> Self {
        Self(SecretBox::new(sk))
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
        PublicKey(self.0.as_secret().public_key())
    }

    pub(crate) fn from_scalar(scalar: &CurveScalar) -> Option<Self> {
        let nz_scalar = SecretBox::new(BackendNonZeroScalar::new(scalar.to_backend_scalar())?);
        Some(Self::new(nz_scalar.as_secret().into()))
    }

    /// Returns a reference to the underlying scalar of the secret key.
    pub(crate) fn to_secret_scalar(&self) -> SecretBox<CurveScalar> {
        let backend_scalar = SecretBox::new(self.0.as_secret().to_secret_scalar());
        SecretBox::new(CurveScalar::from_backend_scalar(backend_scalar.as_secret()))
    }
}

#[cfg(test)]
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_secret_scalar().as_secret() == other.to_secret_scalar().as_secret()
    }
}

impl RepresentableAsArray for SecretKey {
    type Size = <CurveScalar as RepresentableAsArray>::Size;
}

impl SerializableToSecretArray for SecretKey {
    fn to_secret_array(&self) -> SecretBox<GenericArray<u8, Self::Size>> {
        SecretBox::new(self.0.as_secret().to_bytes())
    }
}

impl DeserializableFromArray for SecretKey {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        BackendSecretKey::<CurveType>::from_bytes(arr.as_slice())
            .map(Self::new)
            .map_err(|_| ConstructionError::new("SecretKey", "Internal backend error"))
    }
}

impl HasTypeName for SecretKey {
    fn type_name() -> &'static str {
        "SecretKey"
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_secret::<Self>(f)
    }
}

fn digest_for_signing(message: &[u8]) -> BackendDigest {
    Hash::new().chain_bytes(message).digest()
}

/// An object used to sign messages.
/// For security reasons cannot be serialized.
#[derive(Clone)]
pub struct Signer(SecretKey);

impl Signer {
    /// Creates a new signer out of a secret key.
    pub fn new(sk: &SecretKey) -> Self {
        Self(sk.clone())
    }

    /// Signs the given message using the given RNG.
    pub fn sign_with_rng(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8]) -> Signature {
        let digest = digest_for_signing(message);
        let secret_key = self.0.clone();
        // We could use SecretBox here, but SigningKey does not implement Clone.
        // Box is good enough, seeing as how `signing_key` does not leave this method.
        let signing_key = Box::new(SigningKey::<CurveType>::from(secret_key.0.as_secret()));
        Signature(signing_key.as_ref().sign_digest_with_rng(rng, digest))
    }

    /// Signs the given message using the default RNG.
    #[cfg(feature = "default-rng")]
    #[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_with_rng(&mut OsRng, message)
    }

    /// Returns the public key that can be used to verify the signatures produced by this signer.
    pub fn verifying_key(&self) -> PublicKey {
        self.0.public_key()
    }
}

impl HasTypeName for Signer {
    fn type_name() -> &'static str {
        "Signer"
    }
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_secret::<Self>(f)
    }
}

/// A public key.
///
/// Create using [`SecretKey::public_key`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PublicKey(BackendPublicKey<CurveType>);

impl PublicKey {
    /// Returns the underlying curve point of the public key.
    pub(crate) fn to_point(self) -> CurvePoint {
        CurvePoint::from_backend_point(&self.0.to_projective())
    }

    /// Verifies the signature.
    pub(crate) fn verify_digest(
        &self,
        digest: impl Digest<OutputSize = U32>,
        signature: &Signature,
    ) -> bool {
        let verifier = VerifyingKey::from(&self.0);
        verifier.verify_digest(digest, &signature.0).is_ok()
    }
}

impl RepresentableAsArray for PublicKey {
    type Size = <CurvePoint as RepresentableAsArray>::Size;
}

impl SerializableToArray for PublicKey {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.to_point().to_array()
    }
}

impl DeserializableFromArray for PublicKey {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let cp = CurvePoint::from_array(arr)?;
        BackendPublicKey::<CurveType>::from_affine(cp.to_affine_point())
            .map(Self)
            .map_err(|_| ConstructionError::new("PublicKey", "Internal backend error"))
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Hex)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Hex)
    }
}

impl HasTypeName for PublicKey {
    fn type_name() -> &'static str {
        "PublicKey"
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public(self, f)
    }
}

/// Errors that can happen when using a [`SecretKeyFactory`].
#[derive(Debug, PartialEq)]
pub enum SecretKeyFactoryError {
    /// An internally hashed value is zero.
    /// See [rust-umbral#39](https://github.com/nucypher/rust-umbral/issues/39).
    ZeroHash,
}

impl fmt::Display for SecretKeyFactoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroHash => write!(f, "Resulting secret key is zero"),
        }
    }
}

type SecretKeyFactorySeedSize = U32; // the size of the seed material for key derivation
type SecretKeyFactoryDerivedSize = U64; // the size of the derived key (before hashing to scalar)
type SecretKeyFactorySeed = GenericArray<u8, SecretKeyFactorySeedSize>;

/// This class handles keyring material for Umbral, by allowing deterministic
/// derivation of `SecretKey` objects based on labels.
#[derive(Clone)]
pub struct SecretKeyFactory(SecretBox<SecretKeyFactorySeed>);

impl SecretKeyFactory {
    /// Creates a secret key factory using the given RNG.
    pub fn random_with_rng(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut bytes = SecretBox::new(GenericArray::<u8, SecretKeyFactorySeedSize>::default());
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

    /// Creates a `SecretKey` deterministically from the given label.
    pub fn make_key(&self, label: &[u8]) -> Result<SecretKey, SecretKeyFactoryError> {
        let prefix = b"KEY_DERIVATION/";
        let info: Vec<u8> = prefix
            .iter()
            .cloned()
            .chain(label.iter().cloned())
            .collect();
        let key =
            kdf::<SecretKeyFactorySeed, SecretKeyFactoryDerivedSize>(&self.0, None, Some(&info));
        let scalar = ScalarDigest::new_with_dst(&info)
            .chain_secret_bytes(&key)
            .finalize();
        // TODO (#39) when we can hash to nonzero scalars, we can get rid of returning Result
        SecretKey::from_scalar(&scalar).ok_or(SecretKeyFactoryError::ZeroHash)
    }

    /// Creates a `SecretKeyFactory` deterministically from the given label.
    pub fn make_factory(&self, label: &[u8]) -> Self {
        let prefix = b"FACTORY_DERIVATION/";
        let info: Vec<u8> = prefix
            .iter()
            .cloned()
            .chain(label.iter().cloned())
            .collect();
        let derived_seed =
            kdf::<SecretKeyFactorySeed, SecretKeyFactorySeedSize>(&self.0, None, Some(&info));
        Self(derived_seed)
    }
}

#[cfg(test)]
impl PartialEq for SecretKeyFactory {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_secret() == other.0.as_secret()
    }
}

impl RepresentableAsArray for SecretKeyFactory {
    type Size = SecretKeyFactorySeedSize;
}

impl SerializableToSecretArray for SecretKeyFactory {
    fn to_secret_array(&self) -> SecretBox<GenericArray<u8, Self::Size>> {
        self.0.clone()
    }
}

impl DeserializableFromArray for SecretKeyFactory {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        Ok(Self(SecretBox::new(*arr)))
    }
}

impl HasTypeName for SecretKeyFactory {
    fn type_name() -> &'static str {
        "SecretKeyFactory"
    }
}

impl fmt::Display for SecretKeyFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_secret::<Self>(f)
    }
}

#[cfg(test)]
mod tests {

    use super::{PublicKey, SecretKey, SecretKeyFactory, Signer};
    use crate::{DeserializableFromArray, SerializableToArray, SerializableToSecretArray};

    #[cfg(feature = "serde-support")]
    use crate::serde::tests::{check_deserialization, check_serialization};
    #[cfg(feature = "serde-support")]
    use crate::serde::Representation;

    #[test]
    fn test_serialize_secret_key() {
        let sk = SecretKey::random();
        let sk_arr = sk.to_secret_array();
        let sk_back = SecretKey::from_array(sk_arr.as_secret()).unwrap();
        assert!(sk == sk_back);
    }

    #[test]
    fn test_serialize_secret_key_factory() {
        let skf = SecretKeyFactory::random();
        let skf_arr = skf.to_secret_array();
        let skf_back = SecretKeyFactory::from_array(skf_arr.as_secret()).unwrap();
        assert!(skf == skf_back);
    }

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
    fn test_serialize_public_key() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let pk_arr = pk.to_array();
        let pk_back = PublicKey::from_array(&pk_arr).unwrap();
        assert_eq!(pk, pk_back);
    }

    #[test]
    fn test_sign_and_verify() {
        let sk = SecretKey::random();
        let message = b"asdafdahsfdasdfasd";
        let signer = Signer::new(&sk);
        let signature = signer.sign(message);

        let pk = sk.public_key();
        let vk = signer.verifying_key();

        assert_eq!(pk, vk);
        assert!(signature.verify(&vk, message));
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serde_serialization() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let message = b"asdafdahsfdasdfasd";
        let signer = Signer::new(&sk);
        let signature = signer.sign(message);

        check_serialization(&pk, Representation::Hex);
        check_deserialization(&pk);

        check_serialization(&signature, Representation::Base64);
        check_deserialization(&signature);
    }
}
