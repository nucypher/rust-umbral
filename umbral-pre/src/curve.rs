//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

use core::default::Default;
use core::ops::{Add, Mul, Sub};

use digest::Digest;
use elliptic_curve::bigint::U256; // Note that this type is different from typenum::U256
use elliptic_curve::group::ff::PrimeField;
use elliptic_curve::hash2curve::GroupDigest;
use elliptic_curve::hash2field::ExpandMsgXmd;
use elliptic_curve::ops::Reduce;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, Field, FieldSize, NonZeroScalar, ProjectiveArithmetic, Scalar};
use generic_array::GenericArray;
use k256::{ProjectivePoint, Secp256k1};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::CtOption;
use zeroize::{DefaultIsZeroes, Zeroize};

use crate::secret_box::CanBeZeroizedOnDrop;
use crate::traits::{
    ConstructionError, DeserializableFromArray, HasTypeName, RepresentableAsArray,
    SerializableToArray,
};

pub(crate) type CurveType = Secp256k1;
type CompressedPointSize = <FieldSize<CurveType> as ModulusSize>::CompressedPointSize;

type BackendScalar = Scalar<CurveType>;
pub(crate) type BackendNonZeroScalar = NonZeroScalar<CurveType>;

impl CanBeZeroizedOnDrop for BackendNonZeroScalar {
    fn ensure_zeroized_on_drop(&mut self) {
        self.zeroize()
    }
}

// We have to define newtypes for scalar and point here because the compiler
// is not currently smart enough to resolve `BackendScalar` and `BackendPoint`
// as specific types, so we cannot implement local traits for them.
//
// They also have to be public because Rust isn't smart enough to understand that
//     type PointSize = <Point as RepresentableAsArray>::Size;
// isn't leaking the `Point` (probably because type aliases are just inlined).

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct CurveScalar(BackendScalar);

impl CurveScalar {
    pub(crate) fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    pub(crate) fn one() -> Self {
        Self(BackendScalar::one())
    }
}

impl DefaultIsZeroes for CurveScalar {}

impl CanBeZeroizedOnDrop for CurveScalar {
    fn ensure_zeroized_on_drop(&mut self) {
        self.zeroize()
    }
}

impl RepresentableAsArray for CurveScalar {
    // Currently it's the only size available.
    // A separate scalar size may appear in later versions of `elliptic_curve`.
    type Size = FieldSize<CurveType>;
}

impl SerializableToArray for CurveScalar {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_bytes()
    }
}

impl DeserializableFromArray for CurveScalar {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        // unwrap CtOption into Option
        let maybe_scalar: Option<BackendScalar> = BackendScalar::from_repr(*arr).into();
        maybe_scalar
            .map(Self)
            .ok_or_else(|| ConstructionError::new("CurveScalar", "Internal backend error"))
    }
}

impl HasTypeName for CurveScalar {
    fn type_name() -> &'static str {
        "CurveScalar"
    }
}

#[derive(Clone)]
pub(crate) struct NonZeroCurveScalar(BackendNonZeroScalar);

impl CanBeZeroizedOnDrop for NonZeroCurveScalar {
    fn ensure_zeroized_on_drop(&mut self) {
        self.0.zeroize()
    }
}

impl NonZeroCurveScalar {
    /// Generates a random non-zero scalar (in nearly constant-time).
    pub(crate) fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(BackendNonZeroScalar::random(rng))
    }

    pub(crate) fn from_backend_scalar(source: BackendNonZeroScalar) -> Self {
        Self(source)
    }

    pub(crate) fn as_backend_scalar(&self) -> &BackendNonZeroScalar {
        &self.0
    }

    pub(crate) fn invert(&self) -> Self {
        // At the moment there is no infallible invert() for non-zero scalars
        // (see https://github.com/RustCrypto/elliptic-curves/issues/499).
        // But we know it will never fail.
        let inv = self.0.invert().unwrap();
        // We know that the inversion of a nonzero scalar is nonzero,
        // so it is safe to unwrap again.
        Self(BackendNonZeroScalar::new(inv).unwrap())
    }

    pub(crate) fn from_digest(
        d: impl Digest<OutputSize = <CurveScalar as RepresentableAsArray>::Size>,
    ) -> Self {
        // There's currently no way to make the required digest output size
        // depend on the target scalar size, so we are hardcoding it to 256 bit
        // (that is, equal to the scalar size).
        Self(<BackendNonZeroScalar as Reduce<U256>>::from_be_bytes_reduced(d.finalize()))
    }
}

impl From<NonZeroCurveScalar> for CurveScalar {
    fn from(source: NonZeroCurveScalar) -> Self {
        CurveScalar(*source.0)
    }
}

impl From<&NonZeroCurveScalar> for CurveScalar {
    fn from(source: &NonZeroCurveScalar) -> Self {
        CurveScalar(*source.0)
    }
}

type BackendPoint = <CurveType as ProjectiveArithmetic>::ProjectivePoint;
type BackendPointAffine = AffinePoint<CurveType>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CurvePoint(BackendPoint);

impl CurvePoint {
    pub(crate) fn from_backend_point(point: &BackendPoint) -> Self {
        Self(*point)
    }

    pub(crate) fn generator() -> Self {
        Self(BackendPoint::GENERATOR)
    }

    pub(crate) fn identity() -> Self {
        Self(BackendPoint::IDENTITY)
    }

    pub(crate) fn to_affine_point(self) -> BackendPointAffine {
        self.0.to_affine()
    }

    pub(crate) fn from_compressed_array(
        arr: &GenericArray<u8, CompressedPointSize>,
    ) -> Option<Self> {
        let ep = EncodedPoint::<CurveType>::from_bytes(arr.as_slice()).ok()?;
        // Unwrap CtOption into Option
        let cp_opt: Option<BackendPoint> = BackendPoint::from_encoded_point(&ep).into();
        cp_opt.map(Self)
    }

    fn to_compressed_array(self) -> GenericArray<u8, CompressedPointSize> {
        *GenericArray::<u8, CompressedPointSize>::from_slice(
            self.0.to_affine().to_encoded_point(true).as_bytes(),
        )
    }

    /// Hashes arbitrary data with the given domain separation tag
    /// into a valid EC point of the specified curve, using the algorithm described in the
    /// [IETF hash-to-curve standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
    pub(crate) fn from_data(dst: &[u8], data: &[u8]) -> Option<Self> {
        Some(Self(
            CurveType::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[data], dst).ok()?,
        ))
    }
}

impl Default for CurvePoint {
    fn default() -> Self {
        CurvePoint::identity()
    }
}

impl DefaultIsZeroes for CurvePoint {}

impl CanBeZeroizedOnDrop for CurvePoint {
    fn ensure_zeroized_on_drop(&mut self) {
        self.zeroize()
    }
}

impl Add<&CurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn add(self, other: &CurveScalar) -> CurveScalar {
        CurveScalar(self.0.add(&(other.0)))
    }
}

impl Add<&NonZeroCurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn add(self, other: &NonZeroCurveScalar) -> CurveScalar {
        CurveScalar(self.0.add(&(*other.0)))
    }
}

impl Add<&NonZeroCurveScalar> for &NonZeroCurveScalar {
    type Output = CurveScalar;

    fn add(self, other: &NonZeroCurveScalar) -> CurveScalar {
        CurveScalar(self.0.add(&(*other.0)))
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

impl Sub<&NonZeroCurveScalar> for &NonZeroCurveScalar {
    type Output = CurveScalar;

    fn sub(self, other: &NonZeroCurveScalar) -> CurveScalar {
        CurveScalar(self.0.sub(&(*other.0)))
    }
}

impl Mul<&CurveScalar> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, other: &CurveScalar) -> CurvePoint {
        CurvePoint(self.0.mul(&(other.0)))
    }
}

impl Mul<&NonZeroCurveScalar> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, other: &NonZeroCurveScalar) -> CurvePoint {
        CurvePoint(self.0.mul(&(*other.0)))
    }
}

impl Mul<&CurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn mul(self, other: &CurveScalar) -> CurveScalar {
        CurveScalar(self.0.mul(&(other.0)))
    }
}

impl Mul<&NonZeroCurveScalar> for &CurveScalar {
    type Output = CurveScalar;

    fn mul(self, other: &NonZeroCurveScalar) -> CurveScalar {
        CurveScalar(self.0.mul(&(*other.0)))
    }
}

impl Mul<&NonZeroCurveScalar> for &NonZeroCurveScalar {
    type Output = NonZeroCurveScalar;

    fn mul(self, other: &NonZeroCurveScalar) -> NonZeroCurveScalar {
        NonZeroCurveScalar(self.0.mul(other.0))
    }
}

impl RepresentableAsArray for CurvePoint {
    type Size = CompressedPointSize;
}

impl SerializableToArray for CurvePoint {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.to_compressed_array()
    }
}

impl DeserializableFromArray for CurvePoint {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        Self::from_compressed_array(arr)
            .ok_or_else(|| ConstructionError::new("CurvePoint", "Internal backend error"))
    }
}

impl HasTypeName for CurvePoint {
    fn type_name() -> &'static str {
        "CurvePoint"
    }
}
