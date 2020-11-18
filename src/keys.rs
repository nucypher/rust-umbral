use ecdsa::{SecretKey, VerifyKey, Signature, EncodedPoint, SigningKey};
use elliptic_curve::sec1::{FromEncodedPoint};
use generic_array::GenericArray;
use k256::Secp256k1;
use rand_core::OsRng;
use signature::{Verifier, RandomizedSigner};

use crate::curve::{point_to_bytes, CurvePoint, CurvePointSize, CurveScalar};

#[derive(Clone, Debug)]
pub struct UmbralSignature(Signature<Secp256k1>);

#[derive(Clone, Debug)]
pub struct UmbralPrivateKey {
    secret_key: SecretKey<Secp256k1>,
    public_key: UmbralPublicKey,
}

impl UmbralPrivateKey {
    /// Generates a private key and returns it.
    pub fn generate() -> Self {

        let secret_key = SecretKey::<Secp256k1>::random(&mut OsRng);
        let public_key = EncodedPoint::from_secret_key(&secret_key, true);

        Self {
            secret_key,
            public_key: UmbralPublicKey::new(&public_key),
        }
    }

    pub(crate) fn to_scalar(&self) -> CurveScalar {
        *self.secret_key.secret_scalar()
    }

    pub fn public_key(&self) -> UmbralPublicKey {
        self.public_key
    }

    pub(crate) fn sign(&self, message: &[u8]) -> UmbralSignature {
        let signer = SigningKey::<Secp256k1>::from(&self.secret_key);
        let signature: Signature<Secp256k1> = signer.sign_with_rng(&mut OsRng, message);
        UmbralSignature(signature)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UmbralPublicKey {
    public_key: EncodedPoint<Secp256k1>,
}

impl UmbralPublicKey {
    pub(crate) fn new(public_key: &EncodedPoint<Secp256k1>) -> Self {
        Self {
            public_key: *public_key,
        }
    }

    pub(crate) fn to_point(&self) -> CurvePoint {
        CurvePoint::from_encoded_point(&self.public_key).unwrap()
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CurvePointSize> {
        point_to_bytes(&self.to_point())
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &UmbralSignature) -> bool {
        let verifier = VerifyKey::from_encoded_point(&self.public_key).unwrap();
        verifier.verify(message, &signature.0).is_ok()
    }
}

#[cfg(test)]
mod tests {

    use super::UmbralPrivateKey;

    #[test]
    fn sign_verify() {
        let sk = UmbralPrivateKey::generate();
        let message = b"asdafdahsfdasdfasd";
        let signature = sk.sign(message);
        let pk = sk.public_key();
        assert!(pk.verify(message, &signature));
    }
}
