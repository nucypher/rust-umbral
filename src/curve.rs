//! This module derives common types for curve-related objects
//! from the specific curve type.
//! Also contains some helper functions.

use ecdsa::SecretKey;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::{Curve, ProjectiveArithmetic, Scalar};
use k256::Secp256k1;

use core::ops::Add;
use generic_array::{typenum::U1, GenericArray};
use rand_core::OsRng;

pub(crate) type CurveType = Secp256k1;
pub(crate) type CurvePoint = <CurveType as ProjectiveArithmetic>::ProjectivePoint;
pub(crate) type CurveScalar = Scalar<CurveType>;
pub(crate) type CompressedPointSize = <<CurveType as Curve>::FieldSize as Add<U1>>::Output;
pub(crate) type CurveScalarSize = <CurveType as Curve>::FieldSize;

/// Generates a random non-zero scalar (in nearly constant-time).
pub(crate) fn random_nonzero_scalar() -> CurveScalar {
    let sk = SecretKey::<CurveType>::random(&mut OsRng);
    *sk.secret_scalar()
}

/// Converts a curve point to bytes (for hashing purposes, so the exact format is not important).
pub(crate) fn point_to_bytes(p: &CurvePoint) -> GenericArray<u8, CompressedPointSize> {
    *GenericArray::<u8, CompressedPointSize>::from_slice(
        p.to_affine().to_encoded_point(true).as_bytes(),
    )
}
