use ecdsa::{PublicKey, SecretKey, Signature, Signer, Verifier};
use elliptic_curve::weierstrass::public_key::FromPublicKey;
use elliptic_curve::Generate;
use generic_array::GenericArray;
use k256::AffinePoint;
use k256::Secp256k1;
use rand_core::OsRng;
use signature::RandomizedSigner;
use signature::Verifier as _;

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
        let secret_key = SecretKey::<Secp256k1>::generate(&mut OsRng);
        let public_key = PublicKey::from_secret_key(&secret_key, true).unwrap();

        Self {
            secret_key,
            public_key: UmbralPublicKey::new(&public_key),
        }
    }

    pub(crate) fn to_scalar(&self) -> CurveScalar {
        CurveScalar::from_bytes_reduced(self.secret_key.as_bytes())
    }

    pub fn public_key(&self) -> UmbralPublicKey {
        self.public_key
    }

    pub(crate) fn sign(&self, message: &[u8]) -> UmbralSignature {
        let signer = Signer::new(&self.secret_key).unwrap();
        let signature: Signature<Secp256k1> = signer.sign_with_rng(&mut OsRng, message);
        UmbralSignature(signature)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UmbralPublicKey {
    public_key: PublicKey<Secp256k1>,
}

impl UmbralPublicKey {
    pub(crate) fn new(public_key: &PublicKey<Secp256k1>) -> Self {
        Self {
            public_key: *public_key,
        }
    }

    pub(crate) fn to_point(&self) -> CurvePoint {
        let ap = AffinePoint::from_public_key(&self.public_key);
        CurvePoint::from(ap.unwrap())
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CurvePointSize> {
        point_to_bytes(&self.to_point())
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &UmbralSignature) -> bool {
        let verifier = Verifier::new(&self.public_key).unwrap();
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
