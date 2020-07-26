use crate::curve::{CurveScalar, CurvePoint};
use crate::signing::Signature;

pub enum KeyType {
    NoKey,
    DelegatingOnly,
    ReceivingOnly,
    DelegatingAndReceiving,
}

pub fn serialize_key_type(kt: &KeyType) -> u8 {
    match kt {
        KeyType::NoKey => 0,
        KeyType::DelegatingOnly => 1,
        KeyType::ReceivingOnly => 2,
        KeyType::DelegatingAndReceiving => 3,
    }
}



pub struct KFrag {
    id: CurveScalar, // TODO: just bytes in the original, but judging by how it's created, seems to be a Scalar
    bn_key: CurveScalar,
    point_commitment: CurvePoint,
    point_precursor: CurvePoint,
    signature_for_proxy: Signature,
    signature_for_bob: Signature,
    keys_in_signature: KeyType,
}

impl KFrag {

    pub fn new(id: &CurveScalar, bn_key: &CurveScalar, point_commitment: &CurvePoint,
            point_precursor: &CurvePoint, signature_for_proxy: &Signature,
            signature_for_bob: &Signature, keys_in_signature: Option<KeyType>) -> Self {

        let kt = match keys_in_signature {
            Some(k) => k,
            None => KeyType::DelegatingAndReceiving,
        };

        Self {
            id: *id,
            bn_key: *bn_key,
            point_commitment: *point_commitment,
            point_precursor: *point_precursor,
            signature_for_proxy: *signature_for_proxy,
            signature_for_bob: *signature_for_bob,
            keys_in_signature: kt,
        }
    }
}
