use crate::curve::CurvePoint;
use crate::hashing::unsafe_hash_to_point;
use crate::traits::SerializableToArray;

use generic_array::GenericArray;

/// An object containing shared scheme parameters.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Parameters {
    pub(crate) u: CurvePoint,
}

impl Parameters {
    /// Creates a new parameter object.
    pub fn new() -> Self {
        let g = CurvePoint::generator();
        let g_bytes = g.to_array();

        let parameters_seed = b"NuCypher/UmbralParameters/u";

        // Only fails with a minuscule probability,
        // or if the size of a point is too large for the hasher.
        // In any case, we will notice it in tests.
        let u = unsafe_hash_to_point(&g_bytes, parameters_seed).unwrap();

        Self { u }
    }
}

impl SerializableToArray for Parameters {
    type Size = <CurvePoint as SerializableToArray>::Size;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.u.to_array()
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let u = CurvePoint::take_last(*arr)?;
        Some(Self { u })
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::Parameters;
    use crate::SerializableToArray;

    #[test]
    fn test_serialize() {
        let p = Parameters::new();
        let p_arr = p.to_array();
        let p_back = Parameters::from_array(&p_arr).unwrap();
        assert_eq!(p, p_back);
    }

    #[test]
    fn test_default() {
        let p1 = Parameters::new();
        let p2 = Parameters::default();
        assert_eq!(p1, p2);
    }
}
