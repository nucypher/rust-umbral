//! Private and public keys for Umbral.

use ecdsa::{SecretKey, Signature, SigningKey, VerifyKey};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use generic_array::typenum::U32;
use rand_core::OsRng;
use signature::digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use signature::{DigestVerifier, RandomizedDigestSigner};

use crate::curve::{CurvePoint, CurveScalar, CurveType};

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
    pub(crate) fn sign_digest(
        &self,
        digest: impl BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
    ) -> UmbralSignature {
        let signer = SigningKey::<CurveType>::from(&self.0);
        UmbralSignature(signer.sign_digest_with_rng(OsRng, digest))
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

    /// Serialize the public key.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Verifies the signature.
    pub(crate) fn verify_digest(
        &self,
        digest: impl Digest<OutputSize = U32>,
        signature: &UmbralSignature,
    ) -> bool {
        let verifier = VerifyKey::from_encoded_point(&self.0).unwrap();
        verifier.verify_digest(digest, &signature.0).is_ok()
    }
}

#[cfg(test)]
mod tests {

    use super::{UmbralPublicKey, UmbralSecretKey};
    use sha3::Sha3_256;
    use signature::digest::Digest;

    #[test]
    fn sign_verify() {
        let sk = UmbralSecretKey::generate();
        let message = b"asdafdahsfdasdfasd";
        let digest = Sha3_256::new().chain(message);
        let signature = sk.sign_digest(digest);

        let pk = UmbralPublicKey::from_secret_key(&sk);
        let digest = Sha3_256::new().chain(message);
        assert!(pk.verify_digest(digest, &signature));
    }
}
