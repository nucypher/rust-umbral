use crate::cfrags::CapsuleFrag;
use crate::curve::{point_to_bytes, scalar_to_bytes, CurvePoint, CurveScalar, CurvePointSize, CurveScalarSize};
use crate::keys::UmbralPublicKey;
use crate::kfrags::KFrag;
use crate::params::UmbralParameters;
use crate::random_oracles::hash_to_scalar;
use generic_array::GenericArray;
use generic_array::sequence::Concat;
use core::ops::Add;

#[derive(Clone, Copy, Debug)]
pub struct Capsule {
    pub params: UmbralParameters,
    pub point_e: CurvePoint,
    pub point_v: CurvePoint,
    pub bn_sig: CurveScalar,
}

type CapsuleSize = <<CurvePointSize as Add<CurvePointSize>>::Output as Add<CurveScalarSize>>::Output;

impl Capsule {
    pub fn new(
        params: &UmbralParameters,
        point_e: &CurvePoint,
        point_v: &CurvePoint,
        bn_sig: &CurveScalar,
    ) -> Self {
        let res = Self {
            params: *params,
            point_e: *point_e,
            point_v: *point_v,
            bn_sig: *bn_sig,
        };
        assert!(res.verify());
        res
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CapsuleSize> {
        point_to_bytes(&self.point_e)
            .concat(point_to_bytes(&self.point_v))
            .concat(scalar_to_bytes(&self.bn_sig))
    }

    pub fn with_correctness_keys(
        &self,
        delegating: &UmbralPublicKey,
        receiving: &UmbralPublicKey,
        verifying: &UmbralPublicKey,
    ) -> PreparedCapsule {
        PreparedCapsule {
            capsule: *self,
            delegating_key: *delegating,
            receiving_key: *receiving,
            verifying_key: *verifying,
        }
    }

    pub fn verify(&self) -> bool {
        let g = self.params.g;
        let h = hash_to_scalar(&[self.point_e, self.point_v], None);
        &g * &self.bn_sig == &self.point_v + &(&self.point_e * &h)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PreparedCapsule {
    pub capsule: Capsule,
    pub delegating_key: UmbralPublicKey,
    pub receiving_key: UmbralPublicKey,
    pub verifying_key: UmbralPublicKey,
}

impl PreparedCapsule {
    pub fn verify_cfrag(&self, cfrag: &CapsuleFrag) -> bool {
        cfrag.verify_correctness(
            &self.capsule,
            &self.delegating_key,
            &self.receiving_key,
            &self.verifying_key,
        )
    }

    pub fn verify_kfrag(&self, kfrag: &KFrag) -> bool {
        kfrag.verify(
            &self.verifying_key,
            Some(&self.delegating_key),
            Some(&self.receiving_key),
        )
    }
}
