use elliptic_curve::weierstrass::point::CompressedPointSize;
use elliptic_curve::weierstrass::FromPublicKey;
use elliptic_curve::Curve;
use generic_array::GenericArray;
use k256::AffinePoint;
use k256::CompressedPoint;
pub use k256::ProjectivePoint as CurvePoint;
use k256::PublicKey;
pub use k256::Scalar as CurveScalar;
use k256::Secp256k1;

use rand_core::OsRng;

pub type CurvePointSize = CompressedPointSize<Secp256k1>;
pub type CurveScalarSize = <Secp256k1 as Curve>::ElementSize;

pub fn random_scalar() -> CurveScalar {
    CurveScalar::generate_vartime(&mut OsRng)
}

pub fn point_to_bytes(p: &CurvePoint) -> GenericArray<u8, CurvePointSize> {
    let cp = CompressedPoint::from(p.to_affine().unwrap());
    cp.into_bytes()
}

pub fn scalar_to_bytes(s: &CurveScalar) -> GenericArray<u8, CurveScalarSize> {
    s.to_bytes().into()
}

pub fn bytes_to_point(bytes: &[u8]) -> Option<CurvePoint> {
    // FIXME: Can we transform Option into CtOption directly?
    let pk = PublicKey::from_bytes(bytes).unwrap();
    let ap = AffinePoint::from_public_key(&pk);
    // TODO: Can we transfrom CtOption into Option directly?
    if ap.is_some().into() {
        Some(CurvePoint::from(ap.unwrap()))
    } else {
        None
    }
}
