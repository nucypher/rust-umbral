//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

use core::default::Default;
use core::ops::{Add, Mul, Sub};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use ecdsa::{SecretKey, Signature, SigningKey, VerifyKey};
use elliptic_curve::ff::PrimeField;
use elliptic_curve::scalar::NonZeroScalar;
use elliptic_curve::sec1::{CompressedPointSize, EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{Curve, FromDigest, ProjectiveArithmetic, Scalar};
use generic_array::typenum::U32;
use generic_array::GenericArray;
use k256::Secp256k1;
use rand_core::OsRng;
use signature::{DigestVerifier, RandomizedDigestSigner};
use subtle::CtOption;

use crate::traits::SerializableToArray;

type CurveType = Secp256k1;

type BackendScalar = Scalar<CurveType>;
type BackendNonZeroScalar = NonZeroScalar<CurveType>;

// FIXME: we have to define newtypes for scalar and point here because the compiler
// is not currently smart enough to resolve `BackendScalar` and `BackendPoint`
// as specific types, so we cannot implement local traits for them.

// FIXME: only needed to be `pub` and not `pub(crate)` because it leaks through ArrayLength traits
// in the heapless implementation.
#[derive(Clone, Copy, Debug)]
pub struct CurveScalar(BackendScalar);

impl CurveScalar {
    pub(crate) fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    pub(crate) fn one() -> Self {
        Self(BackendScalar::one())
    }

    /// Generates a random non-zero scalar (in nearly constant-time).
    pub(crate) fn random_nonzero() -> CurveScalar {
        Self(*BackendNonZeroScalar::random(&mut OsRng))
    }

    pub(crate) fn from_digest(
        d: impl Digest<OutputSize = <CurveScalar as SerializableToArray>::Size>,
    ) -> Self {
        Self(BackendScalar::from_digest(d))
    }
}

impl Default for CurveScalar {
    fn default() -> Self {
        Self(BackendScalar::default())
    }
}

impl SerializableToArray for CurveScalar {
    // FIXME: currently it's the only size available.
    // A separate scalar size may appear in later versions of `elliptic_curve`.
    type Size = <CurveType as Curve>::FieldSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        // TODO: what happens if the length of `bytes` is wrong?
        let sized_bytes = GenericArray::<u8, Self::Size>::from_slice(bytes.as_ref());
        Scalar::<CurveType>::from_repr(*sized_bytes).map(Self)
    }
}

type BackendPoint = <CurveType as ProjectiveArithmetic>::ProjectivePoint;

// FIXME: only needed to be `pub` and not `pub(crate)` because it leaks through ArrayLength traits
// in the heapless implementation.
#[derive(Clone, Copy, Debug)]
pub struct CurvePoint(BackendPoint);

impl CurvePoint {
    pub(crate) fn generator() -> Self {
        Self(BackendPoint::generator())
    }

    pub(crate) fn identity() -> Self {
        Self(BackendPoint::identity())
    }
}

impl Add<&CurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn add(self, other: &CurveScalar) -> CurveScalar {
        CurveScalar(self.0.add(&(other.0)))
    }
}

impl Add<&CurvePoint> for &CurvePoint {
    type Output = CurvePoint;

    fn add(self, other: &CurvePoint) -> CurvePoint {
        CurvePoint(self.0.add(&(other.0)))
    }
}

impl Sub<&CurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn sub(self, other: &CurveScalar) -> CurveScalar {
        CurveScalar(self.0.sub(&(other.0)))
    }
}

impl Mul<&CurveScalar> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, other: &CurveScalar) -> CurvePoint {
        CurvePoint(self.0.mul(&(other.0)))
    }
}

impl Mul<&CurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn mul(self, other: &CurveScalar) -> CurveScalar {
        CurveScalar(self.0.mul(&(other.0)))
    }
}

impl PartialEq for CurveScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl PartialEq for CurvePoint {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl SerializableToArray for CurvePoint {
    type Size = CompressedPointSize<CurveType>;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        *GenericArray::<u8, Self::Size>::from_slice(
            self.0.to_affine().to_encoded_point(true).as_bytes(),
        )
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let ep = EncodedPoint::<CurveType>::from_bytes(bytes);
        if ep.is_err() {
            return None;
        }

        let cp = BackendPoint::from_encoded_point(&ep.unwrap());
        if cp.is_some().into() {
            Some(Self(cp.unwrap()))
        } else {
            None
        }
    }
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
    pub(crate) fn to_secret_scalar(&self) -> CurveScalar {
        // TODO: `SecretKey` only returns a reference, but how important is this safety measure?
        // We could return a wrapped reference, and define arithmetic operations for it.
        // But we use this secret scalar to multiply not only points, but other scalars too.
        // So there's no point in hiding the actual value here as long as
        // it is going to be effectively dereferenced in other places.
        CurveScalar(*self.0.secret_scalar())
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

impl SerializableToArray for UmbralSecretKey {
    type Size = <CurveScalar as SerializableToArray>::Size;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        SecretKey::<CurveType>::from_bytes(bytes).ok().map(Self)
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
        CurvePoint(BackendPoint::from_encoded_point(&self.0).unwrap())
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

impl SerializableToArray for UmbralPublicKey {
    type Size = <CurvePoint as SerializableToArray>::Size;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        // EncodedPoint can be compressed or uncompressed,
        // so `to_bytes()` does not have a compile-time size,
        // and we have to do this conversion
        // (we know that in our case it is always compressed).
        *GenericArray::<u8, Self::Size>::from_slice(self.0.as_bytes())
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        EncodedPoint::<CurveType>::from_bytes(bytes).ok().map(Self)
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
