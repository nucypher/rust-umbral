//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

use core::default::Default;
use core::ops::{Add, Mul, Sub};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use ecdsa::{Signature as BackendSignature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::ff::PrimeField;
use elliptic_curve::scalar::NonZeroScalar;
use elliptic_curve::sec1::{CompressedPointSize, EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{
    Curve, FromDigest, ProjectiveArithmetic, PublicKey as BackendPublicKey, Scalar,
    SecretKey as BackendSecretKey,
};
use generic_array::typenum::U32;
use generic_array::GenericArray;
use k256::Secp256k1;
use rand_core::OsRng;
use signature::{DigestVerifier, RandomizedDigestSigner, Signature as SignatureTrait};
use subtle::CtOption;

use crate::traits::SerializableToArray;

type CurveType = Secp256k1;

type BackendScalar = Scalar<CurveType>;
type BackendNonZeroScalar = NonZeroScalar<CurveType>;

// We have to define newtypes for scalar and point here because the compiler
// is not currently smart enough to resolve `BackendScalar` and `BackendPoint`
// as specific types, so we cannot implement local traits for them.
//
// They also have to be public because Rust isn't smart enough to understand that
//     type PointSize = <Point as SerializableToArray>::Size;
// isn't leaking the `Point` (probably because type aliases are just inlined).

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CurveScalar(BackendScalar);

impl CurveScalar {
    pub(crate) fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    pub(crate) fn one() -> Self {
        Self(BackendScalar::one())
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.is_zero().into()
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
    // Currently it's the only size available.
    // A separate scalar size may appear in later versions of `elliptic_curve`.
    type Size = <CurveType as Curve>::FieldSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_bytes()
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        Scalar::<CurveType>::from_repr(*arr).map(Self)
    }
}

type BackendPoint = <CurveType as ProjectiveArithmetic>::ProjectivePoint;

#[derive(Clone, Copy, Debug, PartialEq)]
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

impl SerializableToArray for CurvePoint {
    type Size = CompressedPointSize<CurveType>;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        // NOTE: a point has to be serialized in a compressed format,
        // or `unsafe_hash_to_point` becomes unusable.
        *GenericArray::<u8, Self::Size>::from_slice(
            self.0.to_affine().to_encoded_point(true).as_bytes(),
        )
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let ep = EncodedPoint::<CurveType>::from_bytes(arr.as_slice()).ok()?;
        let cp_opt: Option<BackendPoint> = BackendPoint::from_encoded_point(&ep);
        cp_opt.map(Self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Signature(BackendSignature<CurveType>);

impl SerializableToArray for Signature {
    type Size = SignatureSize<CurveType>;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        *GenericArray::<u8, Self::Size>::from_slice(self.0.as_bytes())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        BackendSignature::<CurveType>::from_bytes(arr.as_slice())
            .ok()
            .map(Self)
    }
}

/// A secret key.
#[derive(Clone, Debug)]
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
        CurveScalar(**self.0.secret_scalar())
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
        CurvePoint(self.0.to_projective())
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
        let backend_pk = BackendPublicKey::<CurveType>::from_affine(cp.0.to_affine()).ok()?;
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
        assert_eq!(sk, sk_back);
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
