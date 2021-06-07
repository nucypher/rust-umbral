use alloc::vec::Vec;
use core::fmt;

use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use ecdsa::{Signature as BackendSignature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::{PublicKey as BackendPublicKey, SecretKey as BackendSecretKey};
use generic_array::GenericArray;
use rand_core::{OsRng, RngCore};
use signature::{DigestVerifier, RandomizedDigestSigner, Signature as SignatureTrait};
use typenum::{U32, U64};

use crate::curve::{BackendNonZeroScalar, CurvePoint, CurveScalar, CurveType};
use crate::dem::kdf;
use crate::hashing::{BackendDigest, Hash, ScalarDigest};
use crate::traits::{
    fmt_public, fmt_secret, ConstructionError, DeserializableFromArray, HasTypeName,
    RepresentableAsArray, SerializableToArray,
};

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

impl Signature {
    /// Verifies that the given message was signed with the secret counterpart of the given key.
    /// The message is hashed internally.
    pub fn verify(&self, verifying_key: &PublicKey, message: &[u8]) -> bool {
        verifying_key.verify_digest(digest_for_signing(message), &self)
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

/// A secret key.
#[derive(Clone)] // No Debug derivation, to avoid exposing the key accidentally.
pub struct SecretKey(BackendSecretKey<CurveType>);

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_secret_scalar() == other.to_secret_scalar()
    }
}

impl SecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        let secret_key = BackendSecretKey::<CurveType>::random(&mut OsRng);
        Self(secret_key)
    }

    pub(crate) fn from_scalar(scalar: &CurveScalar) -> Option<Self> {
        let nz_scalar = BackendNonZeroScalar::new(scalar.to_backend_scalar())?;
        Some(Self(BackendSecretKey::<CurveType>::new(nz_scalar)))
    }

    /// Returns a reference to the underlying scalar of the secret key.
    pub(crate) fn to_secret_scalar(&self) -> CurveScalar {
        // TODO (#8): `BackendSecretKey` only returns a reference,
        // but how important is this safety measure?
        // We could return a wrapped reference, and define arithmetic operations for it.
        // But we use this secret scalar to multiply not only points, but other scalars too.
        // So there's no point in hiding the actual value here as long as
        // it is going to be effectively dereferenced in other places.
        CurveScalar::from_backend_scalar(&*self.0.secret_scalar())
    }

    /// Signs a message using the default RNG.
    pub(crate) fn sign_digest(
        &self,
        digest: impl BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
    ) -> Signature {
        let signer = SigningKey::<CurveType>::from(self.0.clone());
        Signature(signer.sign_digest_with_rng(OsRng, digest))
    }
}

impl RepresentableAsArray for SecretKey {
    type Size = <CurveScalar as RepresentableAsArray>::Size;
}

impl SerializableToArray for SecretKey {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        // TODO (#8): a copy of secret data is created in `to_bytes()`.
        self.0.to_bytes()
    }
}

impl DeserializableFromArray for SecretKey {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        BackendSecretKey::<CurveType>::from_bytes(arr.as_slice())
            .map(Self)
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
#[derive(Clone, PartialEq)] // No Debug derivation, to avoid exposing the key accidentally.
pub struct Signer(SecretKey);

impl Signer {
    /// Creates a new signer out of a secret key.
    pub fn new(sk: &SecretKey) -> Self {
        // TODO (#8): cloning secret data
        Self(sk.clone())
    }

    /// Signs the given message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign_digest(digest_for_signing(message))
    }

    /// Returns the public key that can be used to verify the signatures produced by this signer.
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.0)
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PublicKey(BackendPublicKey<CurveType>);

impl PublicKey {
    /// Creates a public key from a secret key.
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        Self(secret_key.0.public_key())
    }

    /// Returns the underlying curve point of the public key.
    pub(crate) fn to_point(&self) -> CurvePoint {
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
        let cp = CurvePoint::from_array(&arr)?;
        BackendPublicKey::<CurveType>::from_affine(cp.to_affine_point())
            .map(Self)
            .map_err(|_| ConstructionError::new("PublicKey", "Internal backend error"))
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

type SecretKeyFactorySeedSize = U64; // the size of the seed material for key derivation
type SecretKeyFactoryDerivedSize = U64; // the size of the derived key (before hashing to scalar)

/// This class handles keyring material for Umbral, by allowing deterministic
/// derivation of `SecretKey` objects based on labels.
#[derive(Clone, Copy, PartialEq)] // No Debug derivation, to avoid exposing the key accidentally.
pub struct SecretKeyFactory(GenericArray<u8, SecretKeyFactorySeedSize>);

impl SecretKeyFactory {
    /// Creates a random factory.
    pub fn random() -> Self {
        let mut bytes = GenericArray::<u8, SecretKeyFactorySeedSize>::default();
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Creates a `SecretKey` from the given label.
    pub fn secret_key_by_label(&self, label: &[u8]) -> Result<SecretKey, SecretKeyFactoryError> {
        let prefix = b"KEY_DERIVATION/";
        let info: Vec<u8> = prefix
            .iter()
            .cloned()
            .chain(label.iter().cloned())
            .collect();
        let key = kdf::<SecretKeyFactoryDerivedSize>(&self.0, None, Some(&info));
        let scalar = ScalarDigest::new_with_dst(&info)
            .chain_bytes(&key)
            .finalize();
        // TODO (#39) when we can hash to nonzero scalars, we can get rid of returning Result
        SecretKey::from_scalar(&scalar).ok_or(SecretKeyFactoryError::ZeroHash)
    }
}

impl RepresentableAsArray for SecretKeyFactory {
    type Size = SecretKeyFactorySeedSize;
}

impl SerializableToArray for SecretKeyFactory {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        // TODO (#8): a copy of secret data is created.
        self.0
    }
}

impl DeserializableFromArray for SecretKeyFactory {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        Ok(Self(*arr))
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
    use crate::{DeserializableFromArray, SerializableToArray};

    #[test]
    fn test_serialize_secret_key() {
        let sk = SecretKey::random();
        let sk_arr = sk.to_array();
        let sk_back = SecretKey::from_array(&sk_arr).unwrap();
        assert_eq!(sk.to_secret_scalar(), sk_back.to_secret_scalar());
    }

    #[test]
    fn test_serialize_secret_key_factory() {
        let skf = SecretKeyFactory::random();
        let skf_arr = skf.to_array();
        let skf_back = SecretKeyFactory::from_array(&skf_arr).unwrap();
        assert!(skf == skf_back);
    }

    #[test]
    fn test_secret_key_factory() {
        let skf = SecretKeyFactory::random();
        let sk1 = skf.secret_key_by_label(b"foo");
        let sk2 = skf.secret_key_by_label(b"foo");
        let sk3 = skf.secret_key_by_label(b"bar");

        assert!(sk1 == sk2);
        assert!(sk1 != sk3);
    }

    #[test]
    fn test_serialize_public_key() {
        let sk = SecretKey::random();
        let pk = PublicKey::from_secret_key(&sk);
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

        let pk = PublicKey::from_secret_key(&sk);
        let vk = signer.verifying_key();

        assert_eq!(pk, vk);
        assert!(signature.verify(&vk, message));
    }
}
