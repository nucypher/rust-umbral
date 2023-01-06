use core::fmt;

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

use crate::capsule::Capsule;
use crate::curve::{CurvePoint, CurveScalar, NonZeroCurveScalar};
use crate::hashing_ds::{hash_to_cfrag_verification, kfrag_signature_message};
use crate::key_frag::{KeyFrag, KeyFragID};
use crate::keys::{PublicKey, Signature};
use crate::secret_box::SecretBox;
use crate::traits::fmt_public;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub(crate) struct CapsuleFragProof {
    point_e2: CurvePoint,
    point_v2: CurvePoint,
    kfrag_commitment: CurvePoint,
    kfrag_pok: CurvePoint,
    signature: CurveScalar,
    kfrag_signature: Signature,
}

impl CapsuleFragProof {
    #[allow(clippy::many_single_char_names)]
    fn from_kfrag_and_cfrag(
        rng: &mut (impl CryptoRng + RngCore),
        capsule: &Capsule,
        kfrag: KeyFrag,
        cfrag_e1: &CurvePoint,
        cfrag_v1: &CurvePoint,
    ) -> Self {
        let params = capsule.params;

        let rk = kfrag.key;
        let t = SecretBox::new(NonZeroCurveScalar::random(rng));

        // Here are the formulaic constituents shared with `CapsuleFrag::verify()`.

        let e = capsule.point_e;
        let v = capsule.point_v;

        let e1 = cfrag_e1;
        let v1 = cfrag_v1;

        let u = params.u;
        let u1 = kfrag.proof.commitment;

        let e2 = &e * t.as_secret();
        let v2 = &v * t.as_secret();
        let u2 = &u * t.as_secret();

        let h = hash_to_cfrag_verification(&[e, *e1, e2, v, *v1, v2, u, u1, u2]);

        ////////

        let z3 = &(&rk * &h) + t.as_secret();

        Self {
            point_e2: e2,
            point_v2: v2,
            kfrag_commitment: u1,
            kfrag_pok: u2,
            signature: z3,
            kfrag_signature: kfrag.proof.signature_for_receiver,
        }
    }
}

/// A reencrypted fragment of a [`Capsule`] created by a proxy.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CapsuleFrag {
    pub(crate) point_e1: CurvePoint,
    pub(crate) point_v1: CurvePoint,
    pub(crate) kfrag_id: KeyFragID,
    pub(crate) precursor: CurvePoint,
    pub(crate) proof: CapsuleFragProof,
}

impl fmt::Display for CapsuleFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public("CapsuleFrag", &self.kfrag_id, f)
    }
}

/// Possible errors that can be returned by [`CapsuleFrag::verify`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CapsuleFragVerificationError {
    /// Inconsistent internal state leading to signature verification failure.
    IncorrectKeyFragSignature,
    /// Inconsistent internal state leading to commitment verification failure.
    IncorrectReencryption,
}

impl fmt::Display for CapsuleFragVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectKeyFragSignature => write!(f, "Invalid CapsuleFrag signature"),
            Self::IncorrectReencryption => write!(f, "Failed to verify reencryption proof"),
        }
    }
}

impl CapsuleFrag {
    fn reencrypted(
        rng: &mut (impl CryptoRng + RngCore),
        capsule: &Capsule,
        kfrag: KeyFrag,
    ) -> Self {
        let rk = kfrag.key;
        let e1 = &capsule.point_e * &rk;
        let v1 = &capsule.point_v * &rk;
        let id = kfrag.id;
        let precursor = kfrag.precursor;
        let proof = CapsuleFragProof::from_kfrag_and_cfrag(rng, capsule, kfrag, &e1, &v1);

        Self {
            point_e1: e1,
            point_v1: v1,
            kfrag_id: id,
            precursor,
            proof,
        }
    }

    /// Verifies the integrity of the capsule fragment, given the original capsule,
    /// the encrypting party's key, the decrypting party's key, and the signing key.
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::result_large_err)]
    pub fn verify(
        self,
        capsule: &Capsule,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Result<VerifiedCapsuleFrag, (CapsuleFragVerificationError, Self)> {
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
            return Err((
                CapsuleFragVerificationError::IncorrectKeyFragSignature,
                self,
            ));
        }

        // TODO (#46): if one or more of the values here are incorrect,
        // we'll get the wrong `h` (since they're all hashed into it),
        // so perhaps it's enough to check only one of these equations.
        let z = self.proof.signature;
        let correct_reencryption_of_e = &e * &z == &e2 + &(&e1 * &h);
        let correct_reencryption_of_v = &v * &z == &v2 + &(&v1 * &h);
        let correct_rk_commitment = &u * &z == &u2 + &(&u1 * &h);

        if !(correct_reencryption_of_e & correct_reencryption_of_v & correct_rk_commitment) {
            return Err((CapsuleFragVerificationError::IncorrectReencryption, self));
        }

        Ok(VerifiedCapsuleFrag { cfrag: self })
    }

    /// Explicitly skips [`CapsuleFrag::verify`] call.
    /// Useful in cases when the verifying keys are impossible to obtain independently,
    /// or when this capsule frag came from a trusted storage.
    ///
    /// **Warning:** make sure you considered the implications of not enforcing verification.
    pub fn skip_verification(self) -> VerifiedCapsuleFrag {
        VerifiedCapsuleFrag { cfrag: self }
    }
}

/// Verified capsule fragment, good for dencryption.
/// Can be serialized, but cannot be deserialized directly.
/// It can only be obtained from [`CapsuleFrag::verify`] or [`CapsuleFrag::skip_verification`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(Serialize))]
#[cfg_attr(feature = "serde-support", serde(transparent))]
pub struct VerifiedCapsuleFrag {
    cfrag: CapsuleFrag,
}

impl fmt::Display for VerifiedCapsuleFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public("VerifiedCapsuleFrag", &self.cfrag.kfrag_id, f)
    }
}

impl VerifiedCapsuleFrag {
    pub(crate) fn reencrypted(
        rng: &mut (impl CryptoRng + RngCore),
        capsule: &Capsule,
        kfrag: KeyFrag,
    ) -> Self {
        VerifiedCapsuleFrag {
            cfrag: CapsuleFrag::reencrypted(rng, capsule, kfrag),
        }
    }

    /// Clears the verification status from the capsule frag.
    /// Useful for the cases where it needs to be put in the protocol structure
    /// containing [`CapsuleFrag`] types (since those are the ones
    /// that can be serialized/deserialized freely).
    pub fn unverify(self) -> CapsuleFrag {
        self.cfrag
    }
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use super::VerifiedCapsuleFrag;

    use crate::{encrypt, generate_kfrags, reencrypt, Capsule, PublicKey, SecretKey, Signer};

    #[cfg(feature = "serde-support")]
    use crate::serde_bytes::tests::check_serialization_roundtrip;

    fn prepare_cfrags() -> (
        PublicKey,
        PublicKey,
        PublicKey,
        Capsule,
        Box<[VerifiedCapsuleFrag]>,
    ) {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let signer = Signer::new(SecretKey::random());
        let verifying_pk = signer.verifying_key();

        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        let kfrags = generate_kfrags(&delegating_sk, &receiving_pk, &signer, 2, 3, true, true);

        let verified_cfrags: Vec<_> = kfrags
            .iter()
            .map(|kfrag| reencrypt(&capsule, kfrag.clone()))
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

        for verified_cfrag in verified_cfrags.iter() {
            let cfrag = verified_cfrag.clone().unverify();
            let verified_cfrag_back = cfrag
                .verify(&capsule, &verifying_pk, &delegating_pk, &receiving_pk)
                .unwrap();

            assert_eq!(&verified_cfrag_back, verified_cfrag);
        }
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serde_serialization() {
        let (_delegating_pk, _receiving_pk, _verifying_pk, _capsule, verified_cfrags) =
            prepare_cfrags();

        let cfrag = verified_cfrags[0].clone().unverify();

        // Check that the cfrag serializes to the same thing as the verified cfrag
        let cfrag_bytes = rmp_serde::to_vec(&cfrag).unwrap();
        let vcfrag_bytes = rmp_serde::to_vec(&verified_cfrags[0]).unwrap();
        assert_eq!(vcfrag_bytes, cfrag_bytes);

        check_serialization_roundtrip(&cfrag);
    }
}
