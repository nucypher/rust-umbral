use generic_array::GenericArray;
use sha2::{
    digest::{Digest, OutputSizeUser, Update},
    Sha256,
};
use zeroize::Zeroize;

use crate::curve::{CurvePoint, NonZeroCurveScalar};
use crate::secret_box::SecretBox;

// Our hash of choice.
pub(crate) type BackendDigest = Sha256;

pub(crate) type BackendDigestOutput = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

// Wraps BackendDigest for easier replacement, and standardizes the use of DST.
pub(crate) struct Hash(BackendDigest);

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

    pub fn chain_secret_bytes<T: AsRef<[u8]> + Clone + Zeroize>(
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

    pub fn chain_secret_bytes<T: AsRef<[u8]> + Clone + Zeroize>(
        self,
        bytes: &SecretBox<T>,
    ) -> Self {
        Self(self.0.chain_secret_bytes(bytes))
    }

    pub fn chain_point(self, point: &CurvePoint) -> Self {
        self.chain_bytes(point.to_compressed_array())
    }

    pub fn chain_points(self, points: &[CurvePoint]) -> Self {
        let mut digest = self;
        for point in points {
            digest = digest.chain_point(point);
        }
        digest
    }

    pub fn finalize(self) -> NonZeroCurveScalar {
        NonZeroCurveScalar::from_digest(self.0.digest())
    }
}

#[cfg(test)]
mod tests {

    use super::ScalarDigest;
    use crate::curve::{CurvePoint, CurveScalar};

    #[test]
    fn test_scalar_digest() {
        let p1 = CurvePoint::generator();
        let p2 = &p1 + &p1;
        let bytes: &[u8] = b"foobar";

        let s: CurveScalar = ScalarDigest::new_with_dst(b"abc")
            .chain_points(&[p1, p2])
            .chain_bytes(bytes)
            .finalize()
            .into();
        let s_same: CurveScalar = ScalarDigest::new_with_dst(b"abc")
            .chain_points(&[p1, p2])
            .chain_bytes(bytes)
            .finalize()
            .into();
        assert_eq!(s, s_same);

        let s_diff: CurveScalar = ScalarDigest::new_with_dst(b"abc")
            .chain_points(&[p2, p1])
            .chain_bytes(bytes)
            .finalize()
            .into();
        assert_ne!(s, s_diff);

        let s_diff_tag: CurveScalar = ScalarDigest::new_with_dst(b"def")
            .chain_points(&[p1, p2])
            .chain_bytes(bytes)
            .finalize()
            .into();
        assert_ne!(s, s_diff_tag);
    }
}
