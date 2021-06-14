use core::fmt;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::op;

use crate::capsule::Capsule;
use crate::curve::{CurvePoint, CurveScalar};
use crate::hashing_ds::{hash_to_cfrag_verification, kfrag_signature_message};
use crate::key_frag::{KeyFrag, KeyFragID};
use crate::keys::{PublicKey, Signature};
use crate::traits::{
    fmt_public, ConstructionError, DeserializableFromArray, HasTypeName, RepresentableAsArray,
    SerializableToArray,
};

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
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
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

        let h = hash_to_cfrag_verification(&[e, *e1, e2, v, *v1, v2, u, u1, u2]);

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
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
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

impl HasTypeName for CapsuleFrag {
    fn type_name() -> &'static str {
        "CapsuleFrag"
    }
}

impl fmt::Display for CapsuleFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
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

impl fmt::Display for CapsuleFragVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectKeyFragSignature => write!(f, "Invalid KeyFrag signature"),
            Self::IncorrectReencryption => write!(f, "Failed to verify reencryption proof"),
        }
    }
}

impl CapsuleFrag {
    fn reencrypted(capsule: &Capsule, kfrag: &KeyFrag) -> Self {
        let rk = kfrag.key;
        let e1 = &capsule.point_e * &rk;
        let v1 = &capsule.point_v * &rk;
        let proof = CapsuleFragProof::from_kfrag_and_cfrag(&capsule, &kfrag, &e1, &v1);

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
    #[allow(clippy::many_single_char_names)]
    pub fn verify(
        &self,
        capsule: &Capsule,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
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

        let h = hash_to_cfrag_verification(&[e, e1, e2, v, v1, v2, u, u1, u2]);

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

        // TODO (#46): if one or more of the values here are incorrect,
        // we'll get the wrong `h` (since they're all hashed into it),
        // so perhaps it's enough to check only one of these equations.
        let z = self.proof.signature;
        let correct_reencryption_of_e = &e * &z == &e2 + &(&e1 * &h);
        let correct_reencryption_of_v = &v * &z == &v2 + &(&v1 * &h);
        let correct_rk_commitment = &u * &z == &u2 + &(&u1 * &h);

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

impl HasTypeName for VerifiedCapsuleFrag {
    fn type_name() -> &'static str {
        "VerifiedCapsuleFrag"
    }
}

impl fmt::Display for VerifiedCapsuleFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

impl VerifiedCapsuleFrag {
    pub(crate) fn reencrypted(capsule: &Capsule, kfrag: &KeyFrag) -> Self {
        VerifiedCapsuleFrag {
            cfrag: CapsuleFrag::reencrypted(capsule, kfrag),
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
    ) {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let signing_sk = SecretKey::random();
        let signer = Signer::new(&signing_sk);
        let verifying_pk = signing_sk.public_key();

        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        let kfrags = generate_kfrags(&delegating_sk, &receiving_pk, &signer, 2, 3, true, true);

        let verified_cfrags: Vec<_> = kfrags
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag))
            .collect();

        (
            delegating_pk,
            receiving_pk,
            verifying_pk,
            capsule,
            verified_cfrags.into_boxed_slice(),
        )
    }

    #[test]
    fn test_verify() {
        let (delegating_pk, receiving_pk, verifying_pk, capsule, verified_cfrags) =
            prepare_cfrags();

        for verified_cfrag in verified_cfrags.iter().cloned() {
            let cfrag_array = verified_cfrag.to_array();
            let cfrag_back = CapsuleFrag::from_array(&cfrag_array).unwrap();

            assert_eq!(cfrag_back.to_array(), cfrag_array);

            let verified_cfrag_back = cfrag_back
                .verify(&capsule, &verifying_pk, &delegating_pk, &receiving_pk)
                .unwrap();

            assert_eq!(verified_cfrag_back, verified_cfrag);
        }
    }
}
