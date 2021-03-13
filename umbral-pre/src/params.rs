use crate::curve::CurvePoint;
use crate::hashing::unsafe_hash_to_point;

/// An object containing shared scheme parameters.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Parameters {
    pub(crate) u: CurvePoint,
}

impl Parameters {
    /// Creates a new parameter object.
    pub fn new() -> Self {
        // The goal is to find two distinct points `g` and `u` for which `log_g(u)` is unknown.
        // `g` is fixed to be the generator because it has to be the same
        // as the one used for secret/public keys, and it is standardized (for a given curve).

        // Only fails with a minuscule probability,
        // and since `g` is fixed here, we can just ignore the panic branch,
        // because we know it succeeds.

        // Technically, we don't need the DST here now since it's a custom hashing function
        // used for exactly one purpose (and, really, on only one value).
        // But in view of possible replacement with the standard hash-to-curve (see #35),
        // which will need a DST, we're using a DST here as well.
        let u = unsafe_hash_to_point(b"PARAMETERS", b"POINT_U").unwrap();

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
