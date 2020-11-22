use crate::curve::CurvePoint;
use crate::hashing::unsafe_hash_to_point;
use crate::traits::SerializableToArray;

use core::default::Default;
use generic_array::GenericArray;

#[derive(Clone, Copy, Debug)]
pub struct UmbralParameters {
    pub u: CurvePoint,
}

impl UmbralParameters {
    pub fn new() -> Self {
        let g = CurvePoint::generator();
        let g_bytes = g.to_array();

        let parameters_seed = b"NuCypher/UmbralParameters/u";
        let u = unsafe_hash_to_point(&g_bytes, parameters_seed).unwrap();

        Self { u }
    }
}

impl SerializableToArray for UmbralParameters {
    type Size = <CurvePoint as SerializableToArray>::Size;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.u.to_array()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        CurvePoint::from_bytes(bytes).map(|u| Self { u })
    }
}

impl Default for UmbralParameters {
    fn default() -> Self {
        Self::new()
    }
}
