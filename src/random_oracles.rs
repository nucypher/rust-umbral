use blake2::{Blake2b, Digest};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::Sha3_256;
use generic_array::GenericArray;
use generic_array::typenum::{Unsigned, U32};

use crate::curve::{bytes_to_point, point_to_bytes, CurvePoint, CurveScalar, CurvePointSize};

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
    let len_data = (data.len() as u32).to_be_bytes();
    let len_label = (label.len() as u32).to_be_bytes();

    let curve_key_size_bytes = CurvePointSize::to_usize();

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
        let mut hash_digest_full = hash_function.finalize();
        // TODO: check that the digest is long enough?
        let compressed_point = &mut hash_digest_full[0..curve_key_size_bytes];

        // Set the sign byte
        compressed_point[0] = if compressed_point[0] & 1 == 0 { 2 } else { 3 };

        let maybe_point = bytes_to_point(compressed_point);
        if maybe_point.is_some() {
            return maybe_point;
        }

        i += 1
    }

    // Only happens with probability 2^(-32)
    None
}

// TODO: would be more convenient to take anything implementing `to_bytes()` in some form,
// since `customization_string` is used in the same way as `crypto_items`.
pub fn hash_to_scalar(
    crypto_items: &[CurvePoint],
    customization_string: Option<&[u8]>,
) -> CurveScalar {
    // TODO: make generic in hash algorithm (use Digest trait)
    // TODO: the original uses Blake here, but it has
    // the output size not supported by `from_digest()`
    let mut hasher = Sha3_256::new();

    hasher.update(&"hash_to_curvebn");
    match customization_string {
        Some(s) => hasher.update(s),
        None => {}
    };

    for item in crypto_items {
        hasher.update(point_to_bytes(item));
    }

    CurveScalar::from_digest(hasher)
}

// TODO: what's even the point of passing `key_length` then?
pub type KdfSize = U32;

pub fn kdf(
    ecpoint: &CurvePoint,
    key_length: usize,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> GenericArray<u8, KdfSize> {
    let data = point_to_bytes(ecpoint);
    let hk = Hkdf::<Blake2b>::new(salt, &data);

    let mut okm = GenericArray::<u8, KdfSize>::default();

    let def_info = match info {
        Some(x) => x,
        None => &[],
    };

    hk.expand(&def_info, &mut okm);
    okm
}

#[cfg(test)]
mod tests {

    use super::{hash_to_scalar, kdf, unsafe_hash_to_point};
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
        let p = hash_to_scalar(&[p1, p2], None);
        println!("hash_to_scalar: {:?}", p);
    }

    #[test]
    fn test_kdf() {
        let p1 = CurvePoint::generator();
        let salt = b"abcdefg";
        let info = b"sdasdasd";
        let key = kdf(&p1, 128, Some(&salt[..]), Some(&info[..]));
        println!("kdf: {:?}", key);
    }
}
