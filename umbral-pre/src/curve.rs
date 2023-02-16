//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

use alloc::format;
use alloc::string::String;
use core::default::Default;
use core::ops::{Add, Mul, Sub};

use k256::{
    elliptic_curve::{
        bigint::U256, // Note that this type is different from typenum::U256
        generic_array::GenericArray,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        ops::Reduce,
        sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
        Field,
        FieldSize,
        NonZeroScalar,
        ProjectiveArithmetic,
        Scalar,
    },
    Secp256k1,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Digest, Sha256};
use subtle::CtOption;
use zeroize::{DefaultIsZeroes, Zeroize};

#[cfg(any(feature = "serde-support", test))]
use k256::elliptic_curve::group::ff::PrimeField;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde-support")]
use crate::serde_bytes::{
    deserialize_with_encoding, serialize_with_encoding, Encoding, TryFromBytes,
};

pub(crate) type CurveType = Secp256k1;
pub(crate) type CompressedPointSize = <FieldSize<CurveType> as ModulusSize>::CompressedPointSize;

type BackendScalar = Scalar<CurveType>;
pub(crate) type ScalarSize = FieldSize<CurveType>;
pub(crate) type BackendNonZeroScalar = NonZeroScalar<CurveType>;

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

    pub(crate) fn to_array(self) -> k256::FieldBytes {
        self.0.to_bytes()
    }

    #[cfg(any(feature = "serde-support", test))]
    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let arr = GenericArray::<u8, ScalarSize>::from_exact_iter(bytes.iter().cloned())
            .ok_or("Invalid length of a curve scalar")?;

        // unwrap CtOption into Option
        let maybe_scalar: Option<BackendScalar> = BackendScalar::from_repr(arr).into();
        maybe_scalar
            .map(Self)
            .ok_or_else(|| "Invalid curve scalar representation".into())
    }
}

#[cfg(feature = "serde-support")]
impl Serialize for CurveScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_with_encoding(&self.0.to_bytes(), serializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl<'de> Deserialize<'de> for CurveScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl TryFromBytes for CurveScalar {
    type Error = String;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl DefaultIsZeroes for CurveScalar {}

#[derive(Clone, Zeroize)]
pub struct NonZeroCurveScalar(BackendNonZeroScalar);

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

    pub(crate) fn from_digest(d: impl Digest<OutputSize = ScalarSize>) -> Self {
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

/// A point on the elliptic curve.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CurvePoint(BackendPoint);

impl CurvePoint {
    pub(crate) fn from_backend_point(point: &BackendPoint) -> Self {
        Self(*point)
    }

    pub(crate) fn as_backend_point(&self) -> &BackendPoint {
        &self.0
    }

    pub(crate) fn generator() -> Self {
        Self(BackendPoint::GENERATOR)
    }

    pub(crate) fn identity() -> Self {
        Self(BackendPoint::IDENTITY)
    }

    /// Returns `x` and `y` coordinates serialized as big-endian bytes,
    /// or `None` if it is the infinity point.
    pub fn coordinates(&self) -> Option<(k256::FieldBytes, k256::FieldBytes)> {
        let point = self.0.to_encoded_point(false);
        // x() may be None if it is the infinity point.
        // If x() is not None, y() is not None either because we requested
        // an uncompressed point in the line above; can safely unwrap.
        point.x().map(|x| (*x, *point.y().unwrap()))
    }

    pub(crate) fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        let ep = EncodedPoint::<CurveType>::from_bytes(bytes).map_err(|err| format!("{err}"))?;

        // Unwrap CtOption into Option
        let cp_opt: Option<BackendPoint> = BackendPoint::from_encoded_point(&ep).into();
        cp_opt
            .map(Self)
            .ok_or_else(|| "Invalid curve point representation".into())
    }

    pub(crate) fn to_compressed_array(self) -> GenericArray<u8, CompressedPointSize> {
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

#[cfg(feature = "serde-support")]
impl Serialize for CurvePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_with_encoding(&self.to_compressed_array(), serializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl<'de> Deserialize<'de> for CurvePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

#[cfg(feature = "serde-support")]
impl TryFromBytes for CurvePoint {
    type Error = String;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_compressed_bytes(bytes)
    }
}

impl DefaultIsZeroes for CurvePoint {}

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
