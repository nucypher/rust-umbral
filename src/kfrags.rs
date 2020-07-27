use crate::curve::{CurveScalar, CurvePoint, scalar_to_bytes, point_to_bytes};
use crate::keys::{UmbralPublicKey, UmbralSignature};
use crate::params::UmbralParameters;

#[derive(Clone, Copy, Debug)]
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

fn delegating_key_in_signature(kt: &KeyType) -> bool {
    match kt {
        KeyType::DelegatingOnly => true,
        KeyType::DelegatingAndReceiving => true,
        _ => false
    }
}

fn receiving_key_in_signature(kt: &KeyType) -> bool {
    match kt {
        KeyType::ReceivingOnly => true,
        KeyType::DelegatingAndReceiving => true,
        _ => false
    }
}


#[derive(Clone, Debug)]
pub struct KFrag {
    params: UmbralParameters,
    pub id: CurveScalar, // TODO: just bytes in the original, but judging by how it's created, seems to be a Scalar
    pub bn_key: CurveScalar,
    pub point_commitment: CurvePoint,
    pub point_precursor: CurvePoint,
    signature_for_proxy: UmbralSignature,
    pub signature_for_bob: UmbralSignature,
    keys_in_signature: KeyType,
}

impl KFrag {

    pub fn new(
            params: &UmbralParameters,
            id: &CurveScalar, bn_key: &CurveScalar, point_commitment: &CurvePoint,
            point_precursor: &CurvePoint, signature_for_proxy: &UmbralSignature,
            signature_for_bob: &UmbralSignature, keys_in_signature: Option<KeyType>) -> Self {

        let kt = match keys_in_signature {
            Some(k) => k,
            None => KeyType::DelegatingAndReceiving,
        };

        Self {
            params: *params,
            id: *id,
            bn_key: *bn_key,
            point_commitment: *point_commitment,
            point_precursor: *point_precursor,
            signature_for_proxy: signature_for_proxy.clone(),
            signature_for_bob: signature_for_bob.clone(),
            keys_in_signature: kt,
        }
    }

    // FIXME: should it be constant-time?
    pub fn verify(&self,
               signing_pubkey: &UmbralPublicKey,
               delegating_pubkey: Option<&UmbralPublicKey>,
               receiving_pubkey: Option<&UmbralPublicKey>,
               ) -> bool {

        if delegating_key_in_signature(&self.keys_in_signature) {
            // TODO: how to handle it better?
            assert!(delegating_pubkey.is_some());
        }

        if receiving_key_in_signature(&self.keys_in_signature) {
            // TODO: how to handle it better?
            assert!(receiving_pubkey.is_some());
        }

        let u = self.params.u;

        let kfrag_id = self.id;
        let key = self.bn_key;
        let commitment = self.point_commitment;
        let precursor = self.point_precursor;

        //  We check that the commitment is well-formed
        let correct_commitment = commitment == &u * &key;

        // TODO: hide this in a special mutable object associated with Signer?
        let mut kfrag_validity_message: Vec<u8> =
            scalar_to_bytes(&kfrag_id).iter()
            .chain(point_to_bytes(&commitment).iter())
            .chain(point_to_bytes(&precursor).iter())
            .chain([serialize_key_type(&self.keys_in_signature)].iter())
            .copied().collect();

        if delegating_key_in_signature(&self.keys_in_signature) {
            kfrag_validity_message.extend_from_slice(&delegating_pubkey.unwrap().to_bytes());
        }
        if receiving_key_in_signature(&self.keys_in_signature) {
            kfrag_validity_message.extend_from_slice(&receiving_pubkey.unwrap().to_bytes());
        }

        let valid_kfrag_signature = signing_pubkey.verify(&kfrag_validity_message, &self.signature_for_proxy);

        return correct_commitment & valid_kfrag_signature;
    }
}
