use blake2::{Blake2b, Digest};
use sha3::Sha3_256;

// TODO: find a way to create a point directly to avoid importing PublicKey or even AffinePoint too
use k256::AffinePoint;
use k256::PublicKey;

use crate::curve::{CurvePoint, CurveScalar, point_to_bytes, bytes_to_point};


fn to_fixed_be_bytes(x: usize) -> [u8; 4] {
    let data = x.to_be_bytes();
    let l = data.len();
    let s = if l > 4 { 4 } else { l };

    let mut res = [0u8; 4];
    for i in 0..s {
        res[i] = data[i + l - s];
    }
    res
}

/*
Hashes arbitrary data into a valid EC point of the specified curve,
using the try-and-increment method.
It admits an optional label as an additional input to the hash function.
It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.

WARNING: Do not use when the input data is secret, as this implementation is not
in constant time, and hence, it is not safe with respect to timing attacks.
*/

pub fn unsafe_hash_to_point(data: &[u8], label: &[u8]) -> Option<CurvePoint> {

    // FIXME: make it return a constant amount of bytes
    let len_data = to_fixed_be_bytes(data.len());
    let len_label = to_fixed_be_bytes(label.len());

    let label_data: Vec<u8> = len_label.iter()
        .chain(label.iter())
        .chain(len_data.iter())
        .chain(data.iter()).cloned().collect();

    let curve_key_size_bytes = 32; // FIXME: should be taken from the curve

    // We use an internal 32-bit counter as additional input
    let mut i = 0u32;
    while i < <u32>::MAX {
        let ibytes = to_fixed_be_bytes(i as usize);
        let to_hash: Vec<u8> = label_data.iter().chain(&ibytes).cloned().collect();

        // TODO: use a Blake2b implementation that supports personalization (see #155)
        // TODO: use VarBlake2b?
        let mut hash_function = Blake2b::new();
        hash_function.update(to_hash);
        let hash_digest_full = hash_function.finalize();
        // TODO: check that the digest is long enough?
        let hash_digest = &hash_digest_full[0..1+curve_key_size_bytes];

        let sign = if hash_digest[0] & 1 == 0 { b"\x02" } else { b"\x03" };
        let compressed_point: Vec<u8> = sign.iter().chain(hash_digest[1..hash_digest.len()].iter()).cloned().collect();

        let maybe_point = bytes_to_point(&compressed_point);
        if maybe_point.is_some() {
            return maybe_point
        }

        i += 1
    }

    // Only happens with probability 2^(-32)
    None
}


pub fn hash_to_scalar(crypto_items: &[CurvePoint]) -> CurveScalar {
    // TODO: in the original (hashe_to_curvebn()), there is a customization string parameter,
    // but it is never used.
    let customization_string = b"hash_to_curvebn";
    // TODO: make generic in hash algorithm (use Digest trait)
    // TODO: the original uses Blake here, but it has
    // the output size not supported by `from_digest()`
    let mut hasher = Sha3_256::new();
    hasher.update(&customization_string);

    for item in crypto_items {
        hasher.update(point_to_bytes(item));
    }

    CurveScalar::from_digest(hasher)
}


#[cfg(test)]
mod tests {

    use super::{unsafe_hash_to_point, hash_to_scalar};
    use crate::curve::CurvePoint;

    #[test]
    fn test_unsafe_hash_to_point() {
        let data = b"abcdefg";
        let label = b"sdasdasd";
        let p = unsafe_hash_to_point(&data[..], &label[..]);
        println!("unsafe_hash_to_point: {:?}", p);
    }

    #[test]
    fn test_hash_to_scalar() {
        let p1 = CurvePoint::generator();
        let p2 = &p1 + &p1;
        let p = hash_to_scalar(&[p1, p2]);
        println!("hash_to_scalar: {:?}", p);
    }
}
