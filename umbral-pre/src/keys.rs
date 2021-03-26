use alloc::vec::Vec;

use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use ecdsa::{Signature as BackendSignature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::{PublicKey as BackendPublicKey, SecretKey as BackendSecretKey};
use generic_array::GenericArray;
use rand_core::{OsRng, RngCore};
use signature::{DigestVerifier, RandomizedDigestSigner, Signature as SignatureTrait};
use typenum::{U32, U64};

use crate::curve::{BackendNonZeroScalar, CurvePoint, CurveScalar, CurveType};
use crate::dem::kdf;
use crate::hashing::ScalarDigest;
use crate::traits::{DeserializationError, SerializableToArray};

#[derive(Clone, Debug, PartialEq)]
pub struct Signature(BackendSignature<CurveType>);

impl SerializableToArray for Signature {
    type Size = SignatureSize<CurveType>;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        *GenericArray::<u8, Self::Size>::from_slice(self.0.as_bytes())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        // Note that it will not normalize `s` automatically,
        // and if it is not normalized, verification will fail.
        BackendSignature::<CurveType>::from_bytes(arr.as_slice())
            .map(Self)
            .or(Err(DeserializationError::ConstructionFailure))
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

impl SerializableToArray for SecretKey {
    type Size = <CurveScalar as SerializableToArray>::Size;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        // TODO (#8): a copy of secret data is created in `to_bytes()`.
        self.0.to_bytes()
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        BackendSecretKey::<CurveType>::from_bytes(arr.as_slice())
            .map(Self)
            .or(Err(DeserializationError::ConstructionFailure))
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

impl SerializableToArray for PublicKey {
    type Size = <CurvePoint as SerializableToArray>::Size;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.to_point().to_array()
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        let cp = CurvePoint::from_array(&arr)?;
        let backend_pk = BackendPublicKey::<CurveType>::from_affine(cp.to_affine())
            .or(Err(DeserializationError::ConstructionFailure))?;
        Ok(Self(backend_pk))
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

impl SerializableToArray for SecretKeyFactory {
    type Size = SecretKeyFactorySeedSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        // TODO (#8): a copy of secret data is created.
        self.0
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        Ok(Self(*arr))
    }
}

#[cfg(test)]
mod tests {

    use sha2::Sha256;
    use signature::digest::Digest;

    use super::{PublicKey, SecretKey, SecretKeyFactory};
    use crate::SerializableToArray;

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
        let digest = Sha256::new().chain(message);
        let signature = sk.sign_digest(digest);

        let pk = PublicKey::from_secret_key(&sk);
        let digest = Sha256::new().chain(message);
        assert!(pk.verify_digest(digest, &signature));
    }
}
