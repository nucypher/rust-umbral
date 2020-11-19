//! Private and public keys for Umbral.

use ecdsa::{SecretKey, Signature, SigningKey, VerifyKey};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use generic_array::GenericArray;
use rand_core::OsRng;
use signature::{RandomizedSigner, Verifier};

use crate::curve::{point_to_hash_seed, CompressedPointSize, CurvePoint, CurveScalar, CurveType};

#[derive(Clone, Debug)]
pub struct UmbralSignature(Signature<CurveType>);

/// Umbral secret key.
#[derive(Clone, Debug)]
pub struct UmbralSecretKey(SecretKey<CurveType>);

impl UmbralSecretKey {
    /// Generates a secret key using [`OsRng`] and returns it.
    pub fn generate() -> Self {
        let secret_key = SecretKey::<CurveType>::random(&mut OsRng);
        Self(secret_key)
    }

    /// Returns a reference to the underlying scalar of the secret key.
    pub(crate) fn secret_scalar(&self) -> &CurveScalar {
        self.0.secret_scalar()
    }

    /// Signs a message using [`OsRng`].
    pub(crate) fn sign(&self, message: &[u8]) -> UmbralSignature {
        let signer = SigningKey::<CurveType>::from(&self.0);
        let signature: Signature<CurveType> = signer.sign_with_rng(&mut OsRng, message);
        UmbralSignature(signature)
    }
}

/// Umbral public key.
#[derive(Clone, Copy, Debug)]
pub struct UmbralPublicKey(EncodedPoint<CurveType>);

impl UmbralPublicKey {
    /// Creates a public key from a secret key.
    pub fn from_secret_key(secret_key: &UmbralSecretKey) -> Self {
        Self(EncodedPoint::from_secret_key(&secret_key.0, true))
    }

    /// Returns the underlying curve point of the public key.
    pub(crate) fn to_point(&self) -> CurvePoint {
        // TODO: store CurvePoint instead of EncodedPoint?
        CurvePoint::from_encoded_point(&self.0).unwrap()
    }

    /// Converts the public key to bytes (for hashing purposes).
    pub fn to_hash_seed(&self) -> GenericArray<u8, CompressedPointSize> {
        // TODO: since it is used for hashing, we can return just `&[u8]`.
        point_to_hash_seed(&self.to_point())
    }

    /// Verifies the signature.
    pub(crate) fn verify(&self, message: &[u8], signature: &UmbralSignature) -> bool {
        let verifier = VerifyKey::from_encoded_point(&self.0).unwrap();
        verifier.verify(message, &signature.0).is_ok()
    }
}

#[cfg(test)]
mod tests {

    use super::{UmbralSecretKey, UmbralPublicKey};

    #[test]
    fn sign_verify() {
        let sk = UmbralSecretKey::generate();
        let message = b"asdafdahsfdasdfasd";
        let signature = sk.sign(message);
        let pk = UmbralPublicKey::from_secret_key(&sk);
        assert!(pk.verify(message, &signature));
    }
}
