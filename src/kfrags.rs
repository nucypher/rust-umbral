use crate::curve::{point_to_bytes, scalar_to_bytes, CurvePoint, CurvePointSize, CurveScalar};
use crate::keys::{UmbralPublicKey, UmbralSignature};
use crate::params::UmbralParameters;

use generic_array::sequence::Concat;
use generic_array::typenum::U1;
use generic_array::GenericArray;

use core::default::Default;

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    NoKey,
    DelegatingOnly,
    ReceivingOnly,
    DelegatingAndReceiving,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::NoKey
    }
}

pub fn key_type_to_bytes(kt: &KeyType) -> GenericArray<u8, U1> {
    let slice = match kt {
        KeyType::NoKey => [0],
        KeyType::DelegatingOnly => [1],
        KeyType::ReceivingOnly => [2],
        KeyType::DelegatingAndReceiving => [3],
    };
    GenericArray::<u8, U1>::clone_from_slice(&slice)
}

fn delegating_key_in_signature(kt: &KeyType) -> bool {
    match kt {
        KeyType::DelegatingOnly => true,
        KeyType::DelegatingAndReceiving => true,
        _ => false,
    }
}

fn receiving_key_in_signature(kt: &KeyType) -> bool {
    match kt {
        KeyType::ReceivingOnly => true,
        KeyType::DelegatingAndReceiving => true,
        _ => false,
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

impl Default for KFrag {
    fn default() -> Self {
        Self {
            params: UmbralParameters::default(),
            id: CurveScalar::default(),
            bn_key: CurveScalar::default(),
            point_commitment: CurvePoint::identity(),
            point_precursor: CurvePoint::identity(),
            signature_for_proxy: UmbralSignature::default(),
            signature_for_bob: UmbralSignature::default(),
            keys_in_signature: KeyType::default(),
        }
    }
}

impl KFrag {
    pub fn new(
        params: &UmbralParameters,
        id: &CurveScalar,
        bn_key: &CurveScalar,
        point_commitment: &CurvePoint,
        point_precursor: &CurvePoint,
        signature_for_proxy: &UmbralSignature,
        signature_for_bob: &UmbralSignature,
        keys_in_signature: Option<KeyType>,
    ) -> Self {
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
    pub fn verify(
        &self,
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

        // We check that the commitment is well-formed
        let correct_commitment = commitment == &u * &key;

        // TODO: hide this in a special mutable object associated with Signer?
        let kfrag_validity_message = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&precursor))
            .concat(key_type_to_bytes(&self.keys_in_signature));

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.

        let kfrag_validity_message = kfrag_validity_message.concat(
            if delegating_key_in_signature(&self.keys_in_signature) {
                delegating_pubkey.unwrap().to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            },
        );

        let kfrag_validity_message =
            kfrag_validity_message.concat(if receiving_key_in_signature(&self.keys_in_signature) {
                receiving_pubkey.unwrap().to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let valid_kfrag_signature =
            signing_pubkey.verify(&kfrag_validity_message, &self.signature_for_proxy);

        return correct_commitment & valid_kfrag_signature;
    }
}
