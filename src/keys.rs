use crate::params::UmbralParameters;
use crate::curve::{CurvePoint, CurveScalar, random_scalar, point_to_bytes, scalar_to_bytes};

#[derive(Clone, Copy, Debug)]
pub struct UmbralPrivateKey {
    pub params: UmbralParameters,
    pub bn_key: CurveScalar,
    pub pubkey: UmbralPublicKey,
}

#[derive(Clone, Copy, Debug)]
pub struct EllipticCurvePrivateKey();


impl UmbralPrivateKey {

    pub fn new(bn_key: &CurveScalar, params: &UmbralParameters) -> Self {
        let point_key = &(params.g) * &bn_key;
        let pubkey = UmbralPublicKey::new(&point_key, params);
        Self { params: *params, bn_key: *bn_key, pubkey }
    }

    /// Generates a private key and returns it.
    pub fn gen_key(params: &UmbralParameters) -> Self {
        let bn_key = random_scalar();
        Self::new(&bn_key, params)
    }

    pub fn get_pubkey(&self) -> UmbralPublicKey {
        self.pubkey.clone()
    }

    /// Returns a cryptography.io EllipticCurvePrivateKey from the Umbral key.
    pub fn to_cryptography_privkey(&self) -> EllipticCurvePrivateKey {
        // TODO: wait until ECDSA is implemented in k256
        EllipticCurvePrivateKey()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        scalar_to_bytes(&self.bn_key)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UmbralPublicKey {
    pub params: UmbralParameters,
    pub point_key: CurvePoint,
}


impl UmbralPublicKey {
    pub fn new(point_key: &CurvePoint, params: &UmbralParameters) -> Self {
        Self { params: *params, point_key: *point_key }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        point_to_bytes(&self.point_key)
    }
}
