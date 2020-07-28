use crate::curve::{point_to_bytes, CurvePoint};
use crate::random_oracles::unsafe_hash_to_point;

use core::default::Default;

#[derive(Clone, Copy, Debug)]
pub struct UmbralParameters {
    pub g: CurvePoint,
    pub u: CurvePoint,
    pub curve_key_size_bytes: usize,
}

impl UmbralParameters {
    pub fn new() -> Self {
        let curve_key_size_bytes = 32; // TODO: get from the curve

        let g = CurvePoint::generator();
        let g_bytes = point_to_bytes(&g);

        let parameters_seed = b"NuCypher/UmbralParameters/u";
        let u = unsafe_hash_to_point(&g_bytes, parameters_seed).unwrap();

        Self {
            g,
            u,
            curve_key_size_bytes,
        }
    }
}

impl Default for UmbralParameters {
    fn default() -> Self { Self::new() }
}

impl PartialEq for UmbralParameters {
    fn eq(&self, other: &Self) -> bool {
        self.g == other.g
            && self.u == other.u
            && self.curve_key_size_bytes == other.curve_key_size_bytes
    }
}

#[cfg(test)]
mod tests {

    use super::UmbralParameters;

    #[test]
    fn test_params() {
        let p1 = UmbralParameters::new();
        let p2 = UmbralParameters::new();
        assert_eq!(p1, p2);
    }
}
