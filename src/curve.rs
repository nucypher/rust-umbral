use elliptic_curve::{Curve, ProjectiveArithmetic};
use generic_array::GenericArray;
use k256::EncodedPoint;
pub(crate) use k256::Scalar as CurveScalar;
use k256::Secp256k1;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

use rand_core::OsRng;
use core::ops::Add;
use generic_array::typenum::{U1, U32};

pub type CurvePoint = <Secp256k1 as ProjectiveArithmetic>::ProjectivePoint;

// TODO: technically it's CompressedPointSize
pub(crate) type CurvePointSize = <<Secp256k1 as Curve>::FieldSize as Add<U1>>::Output;
// TODO: get rid of hardcoded size
pub(crate) type CurveScalarSize = U32;

pub(crate) fn random_scalar() -> CurveScalar {
    CurveScalar::generate_vartime(&mut OsRng)
}

pub(crate) fn curve_generator() -> CurvePoint {
    CurvePoint::generator()
}

pub(crate) fn point_to_bytes(p: &CurvePoint) -> GenericArray<u8, CurvePointSize> {
    *GenericArray::<u8, CurvePointSize>::from_slice(p.to_affine().to_encoded_point(true).as_bytes())
}

pub(crate) fn scalar_to_bytes(s: &CurveScalar) -> GenericArray<u8, CurveScalarSize> {
    s.to_bytes().into()
}

pub(crate) fn bytes_to_point(bytes: &[u8]) -> Option<CurvePoint> {
    let ep = EncodedPoint::from_bytes(bytes);
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
