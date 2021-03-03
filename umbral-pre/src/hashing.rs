use blake2::VarBlake2b;
use digest::{Digest, Update, VariableOutput};
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use sha3::Sha3_256;

use crate::curve::{CurvePoint, CurveScalar, PublicKey, SecretKey, Signature};
use crate::traits::SerializableToArray;

/// Hashes arbitrary data into a valid EC point of the specified curve,
/// using the try-and-increment method.
/// It admits an optional label as an additional input to the hash function.
/// It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.
///
/// WARNING: Do not use when the input data is secret, as this implementation is not
/// in constant time, and hence, it is not safe with respect to timing attacks.
pub fn unsafe_hash_to_point(data: &[u8], label: &[u8]) -> Option<CurvePoint> {
    // NOTE: Yes, this function is hacky, but it is the only way
    // to hash to a point with an *unknown* discrete log.
    // Don't replace with hashing to scalar and multiplying by a generator!

    let len_data = (data.len() as u32).to_be_bytes();
    let len_label = (label.len() as u32).to_be_bytes();

    type PointSize = <CurvePoint as SerializableToArray>::Size;
    let point_size = PointSize::to_usize();
    let mut arr = GenericArray::<u8, PointSize>::default();

    // We use an internal 32-bit counter as additional input
    let mut i = 0u32;
    while i < <u32>::MAX {
        let ibytes = (i as u32).to_be_bytes();

        // May fail if `point_size` is too large for the hashing algorithm.
        let digest = VarBlake2b::new(point_size).ok()?;
        digest
            .chain(&len_label)
            .chain(label)
            .chain(&len_data)
            .chain(data)
            .chain(&ibytes)
            .finalize_variable(|buf| arr = *GenericArray::<u8, PointSize>::from_slice(buf));

        // Set the sign byte
        let arr_data = arr.as_mut_slice();
        arr_data[0] = if arr_data[0] & 1 == 0 { 2 } else { 3 };

        let maybe_point = CurvePoint::from_bytes(&arr);
        if maybe_point.is_some() {
            return maybe_point;
        }

        i += 1
    }

    // Each iteration can fail with probability 2^(-32), so we probably never reach this point.
    // And even if we do, it's only called once in Parameters::new(), and is easy to notice.
    None
}

pub(crate) struct ScalarDigest(Sha3_256);

// TODO (#2): original uses ExtendedKeccak here
impl ScalarDigest {
    pub fn new() -> Self {
        Self(Sha3_256::new())
    }

    pub fn new_with_dst(bytes: &[u8]) -> Self {
        Self::new().chain_bytes(bytes)
    }

    fn chain_impl(self, bytes: &[u8]) -> Self {
        Self(digest::Digest::chain(self.0, bytes))
    }

    pub fn chain_bytes(self, bytes: &[u8]) -> Self {
        self.chain_impl(bytes)
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
        CurveScalar::from_digest(self.0)
    }
}

pub(crate) struct SignatureDigest(Sha3_256);

impl SignatureDigest {
    pub fn new() -> Self {
        Self(Sha3_256::new())
    }

    fn chain_impl(self, bytes: &[u8]) -> Self {
        Self(digest::Digest::chain(self.0, bytes))
    }

    pub fn chain_scalar(self, scalar: &CurveScalar) -> Self {
        self.chain_impl(&scalar.to_array())
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
        let rs = CurveScalar::random_nonzero();
        let b = true;
        let pk = PublicKey::from_secret_key(&SecretKey::random());

        let signing_sk = SecretKey::random();
        let signing_pk = PublicKey::from_secret_key(&signing_sk);

        let signature = SignatureDigest::new()
            .chain_point(&p2)
            .chain_scalar(&rs)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .sign(&signing_sk);

        let same_values_same_key = SignatureDigest::new()
            .chain_point(&p2)
            .chain_scalar(&rs)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .verify(&signing_pk, &signature);
        assert!(same_values_same_key);

        let same_values_different_key = SignatureDigest::new()
            .chain_point(&p2)
            .chain_scalar(&rs)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .verify(&pk, &signature);

        assert!(!same_values_different_key);

        let different_values_same_key = SignatureDigest::new()
            .chain_point(&p1)
            .chain_scalar(&rs)
            .chain_bool(b)
            .chain_pubkey(&pk)
            .verify(&signing_pk, &signature);

        assert!(!different_values_same_key);
    }
}
