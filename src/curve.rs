//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use ecdsa::{SecretKey, Signature, SigningKey, VerifyKey};
use elliptic_curve::sec1::{CompressedPointSize, EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{Curve, FromDigest, ProjectiveArithmetic, Scalar};
use generic_array::typenum::U32;
use generic_array::GenericArray;
use k256::Secp256k1;
use rand_core::OsRng;
use signature::{DigestVerifier, RandomizedDigestSigner};

pub(crate) type CurveType = Secp256k1;
pub(crate) type CurvePoint = <CurveType as ProjectiveArithmetic>::ProjectivePoint;
pub(crate) type CurveScalar = Scalar<CurveType>;
pub(crate) type CurveCompressedPointSize = CompressedPointSize<CurveType>;
// FIXME: currently it's the only size available.
// A separate scalar size may appear in later versions of `elliptic_curve`.
pub(crate) type CurveScalarSize = <CurveType as Curve>::FieldSize;

/// Generates a random non-zero scalar (in nearly constant-time).
pub(crate) fn random_nonzero_scalar() -> CurveScalar {
    let sk = SecretKey::<CurveType>::random(&mut OsRng);
    *sk.secret_scalar()
}

/// Serializes a point
pub(crate) fn point_to_bytes(p: &CurvePoint) -> GenericArray<u8, CurveCompressedPointSize> {
    *GenericArray::<u8, CurveCompressedPointSize>::from_slice(
        p.to_affine().to_encoded_point(true).as_bytes(),
    )
}

/// Attempts to convert a serialized compressed point to a curve point.
pub(crate) fn bytes_to_compressed_point(
    bytes: &GenericArray<u8, CurveCompressedPointSize>,
) -> Option<CurvePoint> {
    let ep = EncodedPoint::<CurveType>::from_bytes(bytes);
    if ep.is_err() {
        return None;
    }

    let pp = CurvePoint::from_encoded_point(&ep.unwrap());
    if pp.is_some().into() {
        Some(pp.unwrap())
    } else {
        None
    }
}

pub(crate) fn scalar_from_digest(d: impl Digest<OutputSize = CurveScalarSize>) -> CurveScalar {
    CurveScalar::from_digest(d)
}

pub(crate) fn scalar_to_bytes(s: &CurveScalar) -> GenericArray<u8, CurveScalarSize> {
    s.to_bytes()
}

#[derive(Clone, Debug)]
pub struct UmbralSignature(Signature<CurveType>);

/// Umbral secret key.
#[derive(Clone, Debug)]
pub struct UmbralSecretKey(SecretKey<CurveType>);

impl UmbralSecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        let secret_key = SecretKey::<CurveType>::random(&mut OsRng);
        Self(secret_key)
    }

    /// Returns a reference to the underlying scalar of the secret key.
    pub(crate) fn secret_scalar(&self) -> &CurveScalar {
        self.0.secret_scalar()
    }

    /// Signs a message using the default RNG.
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
    pub(crate) fn as_bytes(&self) -> &[u8] {
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
        let sk = UmbralSecretKey::random();
        let message = b"asdafdahsfdasdfasd";
        let digest = Sha3_256::new().chain(message);
        let signature = sk.sign_digest(digest);

        let pk = UmbralPublicKey::from_secret_key(&sk);
        let digest = Sha3_256::new().chain(message);
        assert!(pk.verify_digest(digest, &signature));
    }
}
