use ecdsa::SecretKey;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
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

pub(crate) fn random_scalar() -> CurveScalar {
    let sk = SecretKey::<CurveType>::random(&mut OsRng);
    *sk.secret_scalar()
}

pub(crate) fn point_to_bytes(p: &CurvePoint) -> GenericArray<u8, CompressedPointSize> {
    *GenericArray::<u8, CompressedPointSize>::from_slice(
        p.to_affine().to_encoded_point(true).as_bytes(),
    )
}

pub(crate) fn bytes_to_point(bytes: &[u8]) -> Option<CurvePoint> {
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
