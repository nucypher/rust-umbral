use blake2::{Blake2b, Digest};
use k256::arithmetic::ProjectivePoint as CurvePoint;
use k256::PublicKey;
use k256::arithmetic::AffinePoint;


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

fn unsafe_hash_to_point(data: &[u8], label: &[u8]) -> Option<CurvePoint> {

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

        let mut hash_function = Blake2b::new();
        hash_function.update(to_hash);
        let hash_digest_full = hash_function.finalize();
        // TODO: check that the digest is long enough?
        let hash_digest = &hash_digest_full[0..1+curve_key_size_bytes];

        let sign = if hash_digest[0] & 1 == 0 { b"\x02" } else { b"\x03" };
        let compressed_point: Vec<u8> = sign.iter().chain(hash_digest[1..hash_digest.len()].iter()).cloned().collect();

        let pubkey = PublicKey::from_bytes(compressed_point).unwrap();
        let maybe_point = AffinePoint::from_pubkey(&pubkey);

        if maybe_point.is_some().into() {
            return Some(CurvePoint::from(maybe_point.unwrap()))
        }

        i += 1
    }

    // Only happens with probability 2^(-32)
    None
}


#[cfg(test)]
mod tests {

    use super::unsafe_hash_to_point;

    #[test]
    fn test_unsafe_hash_to_point() {
        let data = b"abcdefg";
        let label = b"sdasdasd";
        let p = unsafe_hash_to_point(&data[..], &label[..]);
        println!("{:?}", p);
    }
}
