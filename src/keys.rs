use ecdsa::{SecretKey, Signature, SigningKey, VerifyKey};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use generic_array::GenericArray;
use rand_core::OsRng;
use signature::{RandomizedSigner, Verifier};

use crate::curve::{point_to_bytes, CompressedPointSize, CurvePoint, CurveScalar, CurveType};

#[derive(Clone, Debug)]
pub struct UmbralSignature(Signature<CurveType>);

#[derive(Clone, Debug)]
pub struct UmbralPrivateKey {
    secret_key: SecretKey<CurveType>,
    public_key: UmbralPublicKey,
}

impl UmbralPrivateKey {
    /// Generates a private key and returns it.
    pub fn generate() -> Self {
        let secret_key = SecretKey::<CurveType>::random(&mut OsRng);
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
        let signer = SigningKey::<CurveType>::from(&self.secret_key);
        let signature: Signature<CurveType> = signer.sign_with_rng(&mut OsRng, message);
        UmbralSignature(signature)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UmbralPublicKey {
    public_key: EncodedPoint<CurveType>,
}

impl UmbralPublicKey {
    pub(crate) fn new(public_key: &EncodedPoint<CurveType>) -> Self {
        Self {
            public_key: *public_key,
        }
    }

    pub(crate) fn to_point(&self) -> CurvePoint {
        CurvePoint::from_encoded_point(&self.public_key).unwrap()
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CompressedPointSize> {
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
