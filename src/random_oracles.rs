use blake2::{Blake2b, Digest};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use elliptic_curve::FromDigest;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use sha3::Sha3_256;

use crate::curve::{
    point_to_bytes, scalar_to_bytes, CompressedPointSize, CurvePoint, CurveScalar, CurveType,
};
use crate::keys::{UmbralPublicKey, UmbralSecretKey, UmbralSignature};

/// Attempts to convert a serialized compressed point to a curve point.
fn bytes_to_compressed_point(bytes: &GenericArray<u8, CompressedPointSize>) -> Option<CurvePoint> {
    let ep = EncodedPoint::<CurveType>::from_bytes(bytes);
    if ep.is_err() {
        return None;
    }

    let pp = CurvePoint::from_encoded_point(&ep.unwrap());
    if pp.is_some().into() {
        Some(pp.unwrap())
    } else {
        None
    }
}

/// Hashes arbitrary data into a valid EC point of the specified curve,
/// using the try-and-increment method.
/// It admits an optional label as an additional input to the hash function.
/// It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.
///
/// WARNING: Do not use when the input data is secret, as this implementation is not
/// in constant time, and hence, it is not safe with respect to timing attacks.
pub(crate) fn unsafe_hash_to_point(data: &[u8], label: &[u8]) -> Option<CurvePoint> {
    let len_data = (data.len() as u32).to_be_bytes();
    let len_label = (label.len() as u32).to_be_bytes();

    let curve_key_size_bytes = CompressedPointSize::to_usize();

    // We use an internal 32-bit counter as additional input
    let mut i = 0u32;
    while i < <u32>::MAX {
        let ibytes = (i as u32).to_be_bytes();

        // TODO: use a Blake2b implementation that supports personalization (see #155)
        // TODO: use VarBlake2b?
        let mut hash_function = Blake2b::new();
        hash_function.update(&len_label);
        hash_function.update(label);
        hash_function.update(&len_data);
        hash_function.update(data);
        hash_function.update(&ibytes);
        let hash_digest_full = hash_function.finalize();
        // TODO: check that the digest is long enough?
        let mut arr = *GenericArray::<u8, CompressedPointSize>::from_slice(
            &hash_digest_full[0..curve_key_size_bytes],
        );

        // Set the sign byte
        let arr_data = arr.as_mut_slice();
        arr_data[0] = if arr_data[0] & 1 == 0 { 2 } else { 3 };

        let maybe_point = bytes_to_compressed_point(&arr);
        if maybe_point.is_some() {
            return maybe_point;
        }

        i += 1
    }

    // Only happens with probability 2^(-32)
    // TODO: increment the whole scalar to reduce the fail probability?
    // And how exactly was this probability calculated?
    None
}

pub(crate) struct ScalarDigest(Sha3_256);

// TODO: original uses ExtendedKeccak here
impl ScalarDigest {
    pub fn new() -> Self {
        Self(Sha3_256::new()).chain_bytes(b"hash_to_curvebn")
    }

    pub fn chain_bytes(self, bytes: &[u8]) -> Self {
        Self(self.0.chain(bytes))
    }

    pub fn chain_scalar(self, scalar: &CurveScalar) -> Self {
        Self(self.0.chain(&scalar_to_bytes(scalar)))
    }

    pub fn chain_point(self, point: &CurvePoint) -> Self {
        Self(self.0.chain(&point_to_bytes(point)))
    }

    pub fn chain_points(self, points: &[CurvePoint]) -> Self {
        let mut digest = self;
        for point in points {
            digest = digest.chain_point(&point);
        }
        digest
    }

    pub fn finalize(self) -> CurveScalar {
        CurveScalar::from_digest(self.0)
    }
}

pub(crate) struct SignatureDigest(Sha3_256);

impl SignatureDigest {
    pub fn new() -> Self {
        Self(Sha3_256::new())
    }

    pub fn chain_scalar(self, scalar: &CurveScalar) -> Self {
        Self(self.0.chain(&scalar_to_bytes(scalar)))
    }

    pub fn chain_point(self, point: &CurvePoint) -> Self {
        Self(self.0.chain(&point_to_bytes(point)))
    }

    pub fn chain_pubkey(self, pk: &UmbralPublicKey) -> Self {
        Self(self.0.chain(pk.as_bytes()))
    }

    pub fn chain_bool(self, val: bool) -> Self {
        Self(self.0.chain(&[val as u8]))
    }

    pub fn sign(self, sk: &UmbralSecretKey) -> UmbralSignature {
        sk.sign_digest(self.0)
    }

    pub fn verify(self, pk: &UmbralPublicKey, signature: &UmbralSignature) -> bool {
        pk.verify_digest(self.0, signature)
    }
}

#[cfg(test)]
mod tests {

    use super::{unsafe_hash_to_point, ScalarDigest};
    use crate::curve::CurvePoint;

    #[test]
    fn test_unsafe_hash_to_point() {
        let data = b"abcdefg";
        let label = b"sdasdasd";
        let p = unsafe_hash_to_point(&data[..], &label[..]);
        let p_same = unsafe_hash_to_point(&data[..], &label[..]);
        assert_eq!(p, p_same);

        let data2 = b"abcdefgh";
        let p_data2 = unsafe_hash_to_point(&data2[..], &label[..]);
        assert_ne!(p, p_data2);

        let label2 = b"sdasdasds";
        let p_label2 = unsafe_hash_to_point(&data[..], &label2[..]);
        assert_ne!(p, p_label2);
    }

    #[test]
    fn test_hash_to_scalar() {
        let p1 = CurvePoint::generator();
        let p2 = &p1 + &p1;
        let s = ScalarDigest::new().chain_points(&[p1, p2]).finalize();
        let s_same = ScalarDigest::new().chain_points(&[p1, p2]).finalize();
        assert_eq!(s, s_same);

        let s_diff = ScalarDigest::new().chain_points(&[p2, p1]).finalize();
        assert_ne!(s, s_diff);
    }
}
