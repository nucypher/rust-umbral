#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

use crate::curve::CurvePoint;

/// An object containing shared scheme parameters.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Parameters {
    pub(crate) u: CurvePoint,
}

impl Parameters {
    /// Creates a new parameter object.
    pub fn new() -> Self {
        // The goal is to find two distinct points `g` and `u` for which `log_g(u)` is unknown.
        // `g` is fixed to be the generator because it has to be the same
        // as the one used for secret/public keys, and it is standardized (for a given curve).

        // Only fails when the given binary string is too large, which is not the case here,
        // so we can safely unwrap.
        let u = CurvePoint::from_data(b"PARAMETERS", b"POINT_U").unwrap();

        Self { u }
    }
}

#[cfg(test)]
mod tests {

    use super::Parameters;

    #[test]
    fn test_default() {
        let p1 = Parameters::new();
        let p2 = Parameters::new();
        assert_eq!(p1, p2);
    }
}
