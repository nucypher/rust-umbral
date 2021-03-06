use digest::Digest;
use generic_array::sequence::Concat;
use generic_array::GenericArray;
use sha2::Sha256;
use typenum::U1;

use crate::curve::{CurvePoint, CurveScalar, PublicKey, SecretKey, Signature};
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

    let dst_len = (dst.len() as u32).to_be_bytes();
    let data_len = (data.len() as u32).to_be_bytes();

    // We use an internal 32-bit counter as additional input
    let mut i = 0u32;
    while i < <u32>::MAX {
        let ibytes = (i as u32).to_be_bytes();

        let mut digest = Sha256::new();
        digest.update(&dst_len);
        digest.update(dst);
        digest.update(&data_len);
        digest.update(data);
        digest.update(&ibytes);
        let result = digest.finalize();

        // Set the sign byte
        let maybe_point_bytes = sign_prefix.concat(result);

        let maybe_point = CurvePoint::from_bytes(&maybe_point_bytes);
        if maybe_point.is_some() {
            return maybe_point;
        }

        i += 1
    }

    // Each iteration can fail with probability 2^(-32), so we probably never reach this point.
    // And even if we do, it's only called once in Parameters::new(), and is easy to notice.
    None
}

pub(crate) struct ScalarDigest(Sha256);

impl ScalarDigest {
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn new_with_dst(bytes: &[u8]) -> Self {
        Self::new().chain_bytes(bytes)
    }

    fn chain_impl(self, bytes: &[u8]) -> Self {
        Self(digest::Digest::chain(self.0, bytes))
    }

    pub fn chain_bytes<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        self.chain_impl(bytes.as_ref())
    }

    pub fn chain_scalar(self, scalar: &CurveScalar) -> Self {
        self.chain_impl(&scalar.to_array())
    }

    pub fn chain_point(self, point: &CurvePoint) -> Self {
        self.chain_impl(&point.to_array())
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
        CurveScalar::from_digest(self.0)
    }
}

pub(crate) struct SignatureDigest(Sha256);

impl SignatureDigest {
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    fn chain_impl(self, bytes: &[u8]) -> Self {
        Self(digest::Digest::chain(self.0, bytes))
    }

    pub fn chain_bytes<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        self.chain_impl(bytes.as_ref())
    }

    pub fn chain_point(self, point: &CurvePoint) -> Self {
        self.chain_impl(&point.to_array())
    }

    pub fn chain_pubkey(self, pk: &PublicKey) -> Self {
        self.chain_impl(&pk.to_array())
    }

    pub fn chain_bool(self, val: bool) -> Self {
        self.chain_impl(&[val as u8])
    }

    pub fn sign(self, sk: &SecretKey) -> Signature {
        sk.sign_digest(self.0)
    }

    pub fn verify(self, pk: &PublicKey, signature: &Signature) -> bool {
        pk.verify_digest(self.0, signature)
    }
}

#[cfg(test)]
mod tests {

    use super::{unsafe_hash_to_point, ScalarDigest, SignatureDigest};
    use crate::curve::{CurvePoint, CurveScalar, PublicKey, SecretKey};

    #[test]
    fn test_unsafe_hash_to_point() {
        let data = b"abcdefg";
        let dst = b"sdasdasd";
        let p = unsafe_hash_to_point(&dst[..], &data[..]);
        let p_same = unsafe_hash_to_point(&dst[..], &data[..]);
        assert_eq!(p, p_same);

        let data2 = b"abcdefgh";
        let p_data2 = unsafe_hash_to_point(&dst[..], &data2[..]);
        assert_ne!(p, p_data2);

        let dst2 = b"sdasdasds";
        let p_dst2 = unsafe_hash_to_point(&dst2[..], &data[..]);
        assert_ne!(p, p_dst2);
    }

    #[test]
    fn test_scalar_digest() {
        let p1 = CurvePoint::generator();
        let p2 = &p1 + &p1;
        let rs = CurveScalar::random_nonzero();
        let bytes: &[u8] = b"foobar";

        let s = ScalarDigest::new()
            .chain_points(&[p1, p2])
            .chain_scalar(&rs)
            .chain_bytes(bytes)
            .finalize();
        let s_same = ScalarDigest::new()
            .chain_points(&[p1, p2])
            .chain_scalar(&rs)
            .chain_bytes(bytes)
            .finalize();
        assert_eq!(s, s_same);

        let s_diff = ScalarDigest::new()
            .chain_points(&[p2, p1])
            .chain_scalar(&rs)
            .chain_bytes(bytes)
            .finalize();
        assert_ne!(s, s_diff);
    }

    #[test]
    fn test_signature_digest() {
        let p1 = CurvePoint::generator();
        let p2 = &p1 + &p1;
        let bytes = b"asdfghjk";
        let b = true;
        let pk = PublicKey::from_secret_key(&SecretKey::random());

        let signing_sk = SecretKey::random();
        let signing_pk = PublicKey::from_secret_key(&signing_sk);

        let signature = SignatureDigest::new()
            .chain_point(&p2)
            .chain_bytes(&bytes)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .sign(&signing_sk);

        let same_values_same_key = SignatureDigest::new()
            .chain_point(&p2)
            .chain_bytes(&bytes)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .verify(&signing_pk, &signature);
        assert!(same_values_same_key);

        let same_values_different_key = SignatureDigest::new()
            .chain_point(&p2)
            .chain_bytes(&bytes)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .verify(&pk, &signature);

        assert!(!same_values_different_key);

        let different_values_same_key = SignatureDigest::new()
            .chain_point(&p1)
            .chain_bytes(&bytes)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .verify(&signing_pk, &signature);

        assert!(!different_values_same_key);
    }
}
