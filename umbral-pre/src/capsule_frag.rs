use crate::capsule::Capsule;
use crate::curve::{CurvePoint, CurveScalar};
use crate::hashing_ds::{hash_to_cfrag_verification, kfrag_signature_message};
use crate::key_frag::{KeyFrag, KeyFragID};
use crate::keys::{PublicKey, Signature};
use crate::traits::{
    DeserializableFromArray, DeserializationError, RepresentableAsArray, SerializableToArray,
};

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::op;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CapsuleFragProof {
    point_e2: CurvePoint,
    point_v2: CurvePoint,
    kfrag_commitment: CurvePoint,
    kfrag_pok: CurvePoint,
    signature: CurveScalar,
    kfrag_signature: Signature,
}

type PointSize = <CurvePoint as RepresentableAsArray>::Size;
type ScalarSize = <CurveScalar as RepresentableAsArray>::Size;
type SignatureSize = <Signature as RepresentableAsArray>::Size;
type CapsuleFragProofSize =
    op!(PointSize + PointSize + PointSize + PointSize + ScalarSize + SignatureSize);

impl RepresentableAsArray for CapsuleFragProof {
    type Size = CapsuleFragProofSize;
}

impl SerializableToArray for CapsuleFragProof {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.point_e2
            .to_array()
            .concat(self.point_v2.to_array())
            .concat(self.kfrag_commitment.to_array())
            .concat(self.kfrag_pok.to_array())
            .concat(self.signature.to_array())
            .concat(self.kfrag_signature.to_array())
    }
}

impl DeserializableFromArray for CapsuleFragProof {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        let (point_e2, rest) = CurvePoint::take(*arr)?;
        let (point_v2, rest) = CurvePoint::take(rest)?;
        let (kfrag_commitment, rest) = CurvePoint::take(rest)?;
        let (kfrag_pok, rest) = CurvePoint::take(rest)?;
        let (signature, rest) = CurveScalar::take(rest)?;
        let kfrag_signature = Signature::take_last(rest)?;
        Ok(Self {
            point_e2,
            point_v2,
            kfrag_commitment,
            kfrag_pok,
            signature,
            kfrag_signature,
        })
    }
}

impl CapsuleFragProof {
    #[allow(clippy::many_single_char_names)]
    fn from_kfrag_and_cfrag(
        capsule: &Capsule,
        kfrag: &KeyFrag,
        cfrag_e1: &CurvePoint,
        cfrag_v1: &CurvePoint,
        metadata: Option<&[u8]>,
    ) -> Self {
        let params = capsule.params;

        let rk = kfrag.key;
        let t = CurveScalar::random_nonzero();

        // Here are the formulaic constituents shared with `CapsuleFrag::verify()`.

        let e = capsule.point_e;
        let v = capsule.point_v;

        let e1 = cfrag_e1;
        let v1 = cfrag_v1;

        let u = params.u;
        let u1 = kfrag.proof.commitment;

        let e2 = &e * &t;
        let v2 = &v * &t;
        let u2 = &u * &t;

        let h = hash_to_cfrag_verification(&[e, *e1, e2, v, *v1, v2, u, u1, u2], metadata);

        ////////

        let z3 = &t + &(&rk * &h);

        Self {
            point_e2: e2,
            point_v2: v2,
            kfrag_commitment: u1,
            kfrag_pok: u2,
            signature: z3,
            kfrag_signature: kfrag.proof.signature_for_receiver(),
        }
    }
}

/// A reencrypted fragment of a [`Capsule`] created by a proxy.
#[derive(Clone, Debug, PartialEq)]
pub struct CapsuleFrag {
    pub(crate) point_e1: CurvePoint,
    pub(crate) point_v1: CurvePoint,
    pub(crate) kfrag_id: KeyFragID,
    pub(crate) precursor: CurvePoint,
    pub(crate) proof: CapsuleFragProof,
}

impl RepresentableAsArray for CapsuleFrag {
    type Size = op!(PointSize + PointSize + ScalarSize + PointSize + CapsuleFragProofSize);
}

impl SerializableToArray for CapsuleFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.point_e1
            .to_array()
            .concat(self.point_v1.to_array())
            .concat(self.kfrag_id.to_array())
            .concat(self.precursor.to_array())
            .concat(self.proof.to_array())
    }
}

impl DeserializableFromArray for CapsuleFrag {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        let (point_e1, rest) = CurvePoint::take(*arr)?;
        let (point_v1, rest) = CurvePoint::take(rest)?;
        let (kfrag_id, rest) = KeyFragID::take(rest)?;
        let (precursor, rest) = CurvePoint::take(rest)?;
        let proof = CapsuleFragProof::take_last(rest)?;
        Ok(Self {
            point_e1,
            point_v1,
            kfrag_id,
            precursor,
            proof,
        })
    }
}

/// Possible errors that can be returned by [`CapsuleFrag::verify`].
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CapsuleFragVerificationError {
    /// Inconsistent internal state leading to signature verification failure.
    IncorrectKeyFragSignature,
    /// Inconsistent internal state leading to commitment verification failure.
    IncorrectReencryption,
}

impl CapsuleFrag {
    fn reencrypted(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<&[u8]>) -> Self {
        let rk = kfrag.key;
        let e1 = &capsule.point_e * &rk;
        let v1 = &capsule.point_v * &rk;
        let proof = CapsuleFragProof::from_kfrag_and_cfrag(&capsule, &kfrag, &e1, &v1, metadata);

        Self {
            point_e1: e1,
            point_v1: v1,
            kfrag_id: kfrag.id,
            precursor: kfrag.precursor,
            proof,
        }
    }

    /// Verifies the integrity of the capsule fragment, given the original capsule,
    /// the encrypting party's key, the decrypting party's key, and the signing key.
    pub fn verify(
        &self,
        capsule: &Capsule,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiedCapsuleFrag, CapsuleFragVerificationError> {
        let params = capsule.params;

        // Here are the formulaic constituents shared with
        // `CapsuleFragProof::from_kfrag_and_cfrag`.

        let e = capsule.point_e;
        let v = capsule.point_v;

        let e1 = self.point_e1;
        let v1 = self.point_v1;

        let u = params.u;
        let u1 = self.proof.kfrag_commitment;

        let e2 = self.proof.point_e2;
        let v2 = self.proof.point_v2;
        let u2 = self.proof.kfrag_pok;

        let h = hash_to_cfrag_verification(&[e, e1, e2, v, v1, v2, u, u1, u2], metadata);

        ///////

        let precursor = self.precursor;
        let kfrag_id = self.kfrag_id;

        if !self.proof.kfrag_signature.verify(
            verifying_pk,
            kfrag_signature_message(
                &kfrag_id,
                &u1,
                &precursor,
                Some(delegating_pk),
                Some(receiving_pk),
            )
            .as_ref(),
        ) {
            return Err(CapsuleFragVerificationError::IncorrectKeyFragSignature);
        }

        let z3 = self.proof.signature;
        let correct_reencryption_of_e = &e * &z3 == &e2 + &(&e1 * &h);
        let correct_reencryption_of_v = &v * &z3 == &v2 + &(&v1 * &h);
        let correct_rk_commitment = &u * &z3 == &u2 + &(&u1 * &h);

        if !(correct_reencryption_of_e & correct_reencryption_of_v & correct_rk_commitment) {
            return Err(CapsuleFragVerificationError::IncorrectReencryption);
        }

        Ok(VerifiedCapsuleFrag {
            cfrag: self.clone(),
        })
    }
}

/// Verified capsule fragment, good for dencryption.
/// Can be serialized, but cannot be deserialized directly.
/// It can only be obtained from [`CapsuleFrag::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedCapsuleFrag {
    pub(crate) cfrag: CapsuleFrag,
}

impl RepresentableAsArray for VerifiedCapsuleFrag {
    type Size = <CapsuleFrag as RepresentableAsArray>::Size;
}

impl SerializableToArray for VerifiedCapsuleFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.cfrag.to_array()
    }
}

impl VerifiedCapsuleFrag {
    pub(crate) fn reencrypted(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<&[u8]>) -> Self {
        VerifiedCapsuleFrag {
            cfrag: CapsuleFrag::reencrypted(capsule, kfrag, metadata),
        }
    }
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use super::{CapsuleFrag, VerifiedCapsuleFrag};
    use crate::{
        encrypt, generate_kfrags, reencrypt, Capsule, DeserializableFromArray, PublicKey,
        SecretKey, SerializableToArray, Signer,
    };

    fn prepare_cfrags() -> (
        PublicKey,
        PublicKey,
        PublicKey,
        Capsule,
        Box<[VerifiedCapsuleFrag]>,
        Box<[u8]>,
    ) {
        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let signer = Signer::new(&signing_sk);
        let verifying_pk = PublicKey::from_secret_key(&signing_sk);

        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        let kfrags = generate_kfrags(&delegating_sk, &receiving_pk, &signer, 2, 3, true, true);

        let metadata = b"metadata";
        let verified_cfrags: Vec<_> = kfrags
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag, Some(metadata)))
            .collect();

        (
            delegating_pk,
            receiving_pk,
            verifying_pk,
            capsule,
            verified_cfrags.into_boxed_slice(),
            Box::new(*metadata),
        )
    }

    #[test]
    fn test_verify() {
        let (delegating_pk, receiving_pk, verifying_pk, capsule, verified_cfrags, metadata) =
            prepare_cfrags();

        for verified_cfrag in verified_cfrags.iter().cloned() {
            let cfrag_array = verified_cfrag.to_array();
            let cfrag_back = CapsuleFrag::from_array(&cfrag_array).unwrap();

            assert_eq!(cfrag_back.to_array(), cfrag_array);

            let verified_cfrag_back = cfrag_back
                .verify(
                    &capsule,
                    &verifying_pk,
                    &delegating_pk,
                    &receiving_pk,
                    Some(&metadata),
                )
                .unwrap();

            assert_eq!(verified_cfrag_back, verified_cfrag);
        }
    }
}
