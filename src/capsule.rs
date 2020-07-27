use crate::params::UmbralParameters;
use crate::curve::{CurvePoint, CurveScalar, point_to_bytes, scalar_to_bytes};
use crate::keys::{UmbralPublicKey};
use crate::kfrags::KFrag;

#[derive(Clone, Copy, Debug)]
pub struct Capsule {
    pub params: UmbralParameters,
    pub point_e: CurvePoint,
    pub point_v: CurvePoint,
    pub bn_sig: CurveScalar
}

impl Capsule {
    pub fn new(params: &UmbralParameters, point_e: &CurvePoint, point_v: &CurvePoint, bn_sig: &CurveScalar) -> Self {
        Self {
            params: *params,
            point_e: *point_e,
            point_v: *point_v,
            bn_sig: *bn_sig
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let result: Vec<u8> =
            point_to_bytes(&(self.point_e)).iter()
            .chain(point_to_bytes(&self.point_v).iter())
            .chain(scalar_to_bytes(&self.bn_sig).iter())
            .copied().collect();
        result
    }

    pub fn with_correctness_keys(&self,
            delegating: &UmbralPublicKey,
            receiving: &UmbralPublicKey,
            verifying: &UmbralPublicKey) -> PreparedCapsule {
        PreparedCapsule {
            capsule: *self,
            delegating_key: *delegating,
            receiving_key: *receiving,
            verifying_key: *verifying,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PreparedCapsule {
    pub capsule: Capsule,
    delegating_key: UmbralPublicKey,
    receiving_key: UmbralPublicKey,
    verifying_key: UmbralPublicKey,
}

impl PreparedCapsule {
    /*
    pub fn verify(&self) -> bool {
        self.capsule.verify()
    }

    pub fn verify_cfrag(&self, cfrag: CapsuleFrag) -> bool {
        cfrag.verify_correctness(
            &self.capsule,
            &self.delegating_key,
            &self.receiving_key,
            &self.verifying_key)
    }
    */

    pub fn verify_kfrag(&self, kfrag: &KFrag) -> bool {
        kfrag.verify(&self.verifying_key, Some(&self.delegating_key), Some(&self.receiving_key))
    }

}
