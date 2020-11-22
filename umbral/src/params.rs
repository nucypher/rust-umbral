use crate::curve::{
    bytes_to_compressed_point, point_to_bytes, CurveCompressedPointSize, CurvePoint, Serializable,
};
use crate::hashing::unsafe_hash_to_point;

use core::default::Default;
use generic_array::GenericArray;

#[derive(Clone, Copy, Debug)]
pub struct UmbralParameters {
    pub u: CurvePoint,
}

impl UmbralParameters {
    pub fn new() -> Self {
        let g = CurvePoint::generator();
        let g_bytes = point_to_bytes(&g);

        let parameters_seed = b"NuCypher/UmbralParameters/u";
        let u = unsafe_hash_to_point(&g_bytes, parameters_seed).unwrap();

        Self { u }
    }
}

impl Serializable for UmbralParameters {
    type Size = CurveCompressedPointSize;

    fn to_bytes(&self) -> GenericArray<u8, <Self as Serializable>::Size> {
        point_to_bytes(&self.u)
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        bytes_to_compressed_point(bytes).map(|u| Self { u })
    }
}

impl Default for UmbralParameters {
    fn default() -> Self {
        Self::new()
    }
}
