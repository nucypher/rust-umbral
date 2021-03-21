use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use ecdsa::{Signature as BackendSignature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::{PublicKey as BackendPublicKey, SecretKey as BackendSecretKey};
use generic_array::GenericArray;
use rand_core::OsRng;
use signature::{DigestVerifier, RandomizedDigestSigner, Signature as SignatureTrait};
use typenum::U32;

use crate::curve::{CurvePoint, CurveScalar, CurveType};
use crate::traits::SerializableToArray;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature(BackendSignature<CurveType>);

impl SerializableToArray for Signature {
    type Size = SignatureSize<CurveType>;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        *GenericArray::<u8, Self::Size>::from_slice(self.0.as_bytes())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        // Note that it will not normalize `s` automatically,
        // and if it is not normalized, verification will fail.
        BackendSignature::<CurveType>::from_bytes(arr.as_slice())
            .ok()
            .map(Self)
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

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        BackendSecretKey::<CurveType>::from_bytes(arr.as_slice())
            .ok()
            .map(Self)
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

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let cp = CurvePoint::from_array(&arr)?;
        let backend_pk = BackendPublicKey::<CurveType>::from_affine(cp.to_affine()).ok()?;
        Some(Self(backend_pk))
    }
}

#[cfg(test)]
mod tests {

    use sha2::Sha256;
    use signature::digest::Digest;

    use super::{PublicKey, SecretKey};
    use crate::SerializableToArray;

    #[test]
    fn test_serialize_secret_key() {
        let sk = SecretKey::random();
        let sk_arr = sk.to_array();
        let sk_back = SecretKey::from_array(&sk_arr).unwrap();
        assert_eq!(sk.to_secret_scalar(), sk_back.to_secret_scalar());
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
