use digest::Digest;
use generic_array::sequence::Concat;
use generic_array::GenericArray;
use sha2::Sha256;
use typenum::U1;

use crate::curve::{CurvePoint, CurveScalar};
use crate::secret_box::{CanBeZeroizedOnDrop, SecretBox};
use crate::traits::SerializableToArray;

/// Hashes arbitrary data with the given domain separation tag
/// into a valid EC point of the specified curve,
/// using the try-and-increment method.
///
/// WARNING: Do not use when the input data is secret, as this implementation is not
/// in constant time, and hence, it is not safe with respect to timing attacks.
pub fn unsafe_hash_to_point(dst: &[u8], data: &[u8]) -> Option<CurvePoint> {
    // NOTE: Yes, this function is hacky, but it is the only way
    // to hash to a point with an *unknown* discrete log.
    // Don't replace with hashing to scalar and multiplying by a generator!

    // TODO (#35): use the standard method when it is available in RustCrypto.

    // Fixed sign prefix. Halves the range of the generated points, but we only need one,
    // and it is always the same.
    let sign_prefix = GenericArray::<u8, U1>::from_slice(&[2u8]);

    let data_len = (data.len() as u32).to_be_bytes();

    // We use an internal 32-bit counter as additional input
    let mut i = 0u32;
    while i < <u32>::MAX {
        let result = BytesDigest::new_with_dst(dst)
            .chain_bytes(&data_len)
            .chain_bytes(data)
            .chain_bytes(&i.to_be_bytes())
            .finalize();

        // Set the sign byte
        let maybe_point_bytes = sign_prefix.concat(result);

        let maybe_point = CurvePoint::from_compressed_array(&maybe_point_bytes);
        if let Some(point) = maybe_point {
            return Some(point);
        }

        i += 1
    }

    // Each iteration can fail with probability 2^(-32), so we probably never reach this point.
    // And even if we do, it's only called once in Parameters::new(), and is easy to notice.
    None
}

// Our hash of choice.
pub(crate) type BackendDigest = Sha256;

// Wraps BackendDigest for easier replacement, and standardizes the use of DST.
pub(crate) struct Hash(BackendDigest);

// Can't be put in the `impl` in the current version of Rust.
pub type HashOutputSize = <BackendDigest as Digest>::OutputSize;

impl Hash {
    pub fn new() -> Self {
        Self(BackendDigest::new())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        let dst_len = (dst.len() as u32).to_be_bytes();
        Self::new().chain_bytes(dst_len).chain_bytes(dst)
    }

    pub fn chain_bytes<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        Self(self.0.chain(bytes.as_ref()))
    }

    pub fn chain_secret_bytes<T: AsRef<[u8]> + Clone + CanBeZeroizedOnDrop>(
        self,
        bytes: &SecretBox<T>,
    ) -> Self {
        // Assuming here that the bytes are not saved in `BackendDigest`.
        Self(self.0.chain(bytes.as_secret()))
    }

    pub fn digest(self) -> BackendDigest {
        self.0
    }
}

pub(crate) struct ScalarDigest(Hash);

impl ScalarDigest {
    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self(Hash::new_with_dst(dst))
    }

    pub fn chain_bytes<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        Self(self.0.chain_bytes(bytes))
    }

    pub fn chain_secret_bytes<T: AsRef<[u8]> + Clone + CanBeZeroizedOnDrop>(
        self,
        bytes: &SecretBox<T>,
    ) -> Self {
        Self(self.0.chain_secret_bytes(bytes))
    }

    pub fn chain_point(self, point: &CurvePoint) -> Self {
        self.chain_bytes(&point.to_array())
    }

    pub fn chain_points(self, points: &[CurvePoint]) -> Self {
        let mut digest = self;
        for point in points {
            digest = digest.chain_point(&point);
        }
        digest
    }

    pub fn finalize(self) -> CurveScalar {
        // TODO (#35): use the standard method when it is available in RustCrypto.
        // TODO (#39): Ideally this should return a non-zero scalar.
        //     (when it does, the loop in `KeyFragFactory::new()` can be removed)
        CurveScalar::from_digest(self.0.digest())
    }
}

pub(crate) struct BytesDigest(Hash);

impl BytesDigest {
    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self(Hash::new_with_dst(dst))
    }

    pub fn chain_bytes<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        Self(self.0.chain_bytes(bytes))
    }

    pub fn finalize(self) -> GenericArray<u8, HashOutputSize> {
        self.0.digest().finalize()
    }
}

#[cfg(test)]
mod tests {

    use super::{unsafe_hash_to_point, BytesDigest, HashOutputSize, ScalarDigest};
    use crate::curve::{CurvePoint, CurveScalar};
    use generic_array::GenericArray;

    #[test]
    fn test_unsafe_hash_to_point() {
        let data = b"abcdefg";
        let dst = b"sdasdasd";
        let p: Option<CurvePoint> = unsafe_hash_to_point(&dst[..], &data[..]);
        let p_same: Option<CurvePoint> = unsafe_hash_to_point(&dst[..], &data[..]);
        assert_eq!(p, p_same);

        let data2 = b"abcdefgh";
        let p_data2: Option<CurvePoint> = unsafe_hash_to_point(&dst[..], &data2[..]);
        assert_ne!(p, p_data2);

        let dst2 = b"sdasdasds";
        let p_dst2: Option<CurvePoint> = unsafe_hash_to_point(&dst2[..], &data[..]);
        assert_ne!(p, p_dst2);
    }

    #[test]
    fn test_scalar_digest() {
        let p1 = CurvePoint::generator();
        let p2 = &p1 + &p1;
        let bytes: &[u8] = b"foobar";

        let s: CurveScalar = ScalarDigest::new_with_dst(b"abc")
            .chain_points(&[p1, p2])
            .chain_bytes(bytes)
            .finalize();
        let s_same: CurveScalar = ScalarDigest::new_with_dst(b"abc")
            .chain_points(&[p1, p2])
            .chain_bytes(bytes)
            .finalize();
        assert_eq!(s, s_same);

        let s_diff: CurveScalar = ScalarDigest::new_with_dst(b"abc")
            .chain_points(&[p2, p1])
            .chain_bytes(bytes)
            .finalize();
        assert_ne!(s, s_diff);

        let s_diff_tag: CurveScalar = ScalarDigest::new_with_dst(b"def")
            .chain_points(&[p1, p2])
            .chain_bytes(bytes)
            .finalize();
        assert_ne!(s, s_diff_tag);
    }

    #[test]
    fn test_bytes_digest() {
        let bytes: &[u8] = b"foobar";
        let bytes2: &[u8] = b"barbaz";

        let s: GenericArray<u8, HashOutputSize> = BytesDigest::new_with_dst(b"abc")
            .chain_bytes(bytes)
            .finalize();
        let s_same: GenericArray<u8, HashOutputSize> = BytesDigest::new_with_dst(b"abc")
            .chain_bytes(bytes)
            .finalize();
        assert_eq!(s, s_same);

        let s_diff: GenericArray<u8, HashOutputSize> = BytesDigest::new_with_dst(b"abc")
            .chain_bytes(bytes2)
            .finalize();
        assert_ne!(s, s_diff);

        let s_diff_tag: GenericArray<u8, HashOutputSize> = BytesDigest::new_with_dst(b"def")
            .chain_bytes(bytes)
            .finalize();
        assert_ne!(s, s_diff_tag);
    }
}
