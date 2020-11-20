use crate::curve::{point_to_bytes, CurvePoint};
use crate::hashing::unsafe_hash_to_point;

use core::default::Default;

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

impl Default for UmbralParameters {
    fn default() -> Self {
        Self::new()
    }
}
