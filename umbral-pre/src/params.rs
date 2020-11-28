use crate::curve::CurvePoint;
use crate::hashing::unsafe_hash_to_point;
use crate::traits::SerializableToArray;

use generic_array::GenericArray;

/// An object containing shared scheme parameters.
#[derive(Clone, Copy, Debug)]
pub struct UmbralParameters {
    pub(crate) u: CurvePoint,
}

impl UmbralParameters {
    /// Creates a new parameter object.
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

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let u = CurvePoint::take_last(*arr)?;
        Some(Self { u })
    }
}
