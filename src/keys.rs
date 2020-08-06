use digest::Digest;
use ecdsa::hazmat::{SignPrimitive, VerifyPrimitive};
use ecdsa::Signature;
use generic_array::GenericArray;
use k256::Secp256k1;
use sha3::Sha3_256;

use crate::curve::{
    curve_generator, point_to_bytes, random_scalar, CurvePoint, CurvePointSize, CurveScalar,
};

#[derive(Clone, Debug)]
pub struct UmbralSignature(Signature<Secp256k1>);

#[derive(Clone, Copy, Debug)]
pub struct UmbralPrivateKey {
    scalar: CurveScalar,
    public_key: UmbralPublicKey,
}

impl UmbralPrivateKey {
    /// Generates a private key and returns it.
    pub fn generate() -> Self {
        let secret_scalar = random_scalar();
        let public_point = curve_generator() * &secret_scalar;
        let public_key = UmbralPublicKey::new(&public_point);
        Self {
            scalar: secret_scalar,
            public_key,
        }
    }

    pub(crate) fn to_scalar(&self) -> CurveScalar {
        self.scalar
    }

    pub fn public_key(&self) -> UmbralPublicKey {
        self.public_key
    }

    // TODO: should be moved to impl Signer
    // TODO: should be implemented with high-level Signer trait of SecretKey or Scalar,
    // when it's available in RustCrypto.
    pub(crate) fn sign(&self, message: &[u8]) -> UmbralSignature {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hashed = hasher.finalize();
        let l = hashed.len();

        // FIXME: k should be > 0
        loop {
            let k = random_scalar();
            let res = self
                .scalar
                .try_sign_prehashed(&k, GenericArray::from_slice(&hashed[l - 32..l]));
            match res {
                Ok(sig) => {
                    return UmbralSignature(sig);
                }
                Err(_err) => {
                    continue;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UmbralPublicKey {
    point: CurvePoint,
}

impl UmbralPublicKey {
    pub(crate) fn new(point: &CurvePoint) -> Self {
        Self { point: *point }
    }

    pub(crate) fn to_point(&self) -> CurvePoint {
        self.point
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CurvePointSize> {
        point_to_bytes(&self.point)
    }

    // TODO: should be moved to impl Verifier
    // TODO: should be implemented with high-level Verifier trait of PublicKey or AffinePoint,
    // when it's available in RustCrypto.
    pub(crate) fn verify(&self, message: &[u8], signature: &UmbralSignature) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hashed = hasher.finalize();
        let l = hashed.len();

        let ap = self.point.to_affine().unwrap();
        let res = ap.verify_prehashed(GenericArray::from_slice(&hashed[l - 32..l]), &(signature.0));

        res.is_ok()
    }
}
