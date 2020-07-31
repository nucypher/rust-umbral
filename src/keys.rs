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
    pub bn_key: CurveScalar,
    pub pubkey: UmbralPublicKey,
}

impl UmbralPrivateKey {
    pub fn new(bn_key: &CurveScalar) -> Self {
        let point_key = curve_generator() * &bn_key;
        let pubkey = UmbralPublicKey::new(&point_key);
        Self {
            bn_key: *bn_key,
            pubkey,
        }
    }

    /// Generates a private key and returns it.
    pub fn gen_key() -> Self {
        let bn_key = random_scalar();
        Self::new(&bn_key)
    }

    pub fn get_pubkey(&self) -> UmbralPublicKey {
        self.pubkey.clone()
    }

    // TODO: should be moved to impl Signer
    // TODO: should be implemented with high-level Signer trait of SecretKey or Scalar,
    // when it's available in RustCrypto.
    pub fn sign(&self, message: &[u8]) -> UmbralSignature {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hashed = hasher.finalize();
        let l = hashed.len();

        // FIXME: k should be > 0
        loop {
            let k = random_scalar();
            let res = self
                .bn_key
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
    pub point_key: CurvePoint,
}

impl UmbralPublicKey {
    pub fn new(point_key: &CurvePoint) -> Self {
        Self {
            point_key: *point_key,
        }
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CurvePointSize> {
        point_to_bytes(&self.point_key)
    }

    // TODO: should be moved to impl Verifier
    // TODO: should be implemented with high-level Verifier trait of PublicKey or AffinePoint,
    // when it's available in RustCrypto.
    pub fn verify(&self, message: &[u8], signature: &UmbralSignature) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hashed = hasher.finalize();
        let l = hashed.len();

        let ap = self.point_key.to_affine().unwrap();
        let res = ap.verify_prehashed(GenericArray::from_slice(&hashed[l - 32..l]), &(signature.0));

        match res {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
