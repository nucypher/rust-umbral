use sha2::digest::Digest;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

use crate::curve::{CurvePoint};
use crate::hashing::BackendDigestOutput;
use crate::hashing_ds::{hash_to_cfrag_verification, kfrag_signature_message};
use crate::keys::digest_for_signing;
use crate::params::Parameters;
use crate::{Capsule, PublicKey, VerifiedCapsuleFrag};

#[cfg(feature = "default-serialization")]
use crate::{DefaultDeserialize, DefaultSerialize};

/// A collection of data to prove the validity of reencryption.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ReencryptionEvidence {
    // E points
    pub e: CurvePoint,
    pub ez: CurvePoint,
    pub e1: CurvePoint,
    pub e1h: CurvePoint,
    pub e2: CurvePoint,
    // V points
    pub v: CurvePoint,
    pub vz: CurvePoint,
    pub v1: CurvePoint,
    pub v1h: CurvePoint,
    pub v2: CurvePoint,
    // U points
    pub uz: CurvePoint,
    pub u1: CurvePoint,
    pub u1h: CurvePoint,
    pub u2: CurvePoint,
    // Other data
    pub precursor: CurvePoint,
    #[cfg_attr(feature = "serde-support", serde(with = "crate::serde_bytes::as_hex"))]
    pub kfrag_validity_message_hash: BackendDigestOutput,
    pub kfrag_signature_v: bool,
}

impl ReencryptionEvidence {
    /// Creates the new evidence given the capsule and the reencrypted capsule frag.
    pub fn new(
        capsule: &Capsule,
        vcfrag: &VerifiedCapsuleFrag,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Self {
        let params = Parameters::new();

        let cfrag = vcfrag.clone().unverify();

        let u = params.u;
        let u1 = cfrag.proof.kfrag_commitment;
        let u2 = cfrag.proof.kfrag_pok;

        let h = hash_to_cfrag_verification(&[
            capsule.point_e,
            cfrag.point_e1,
            cfrag.proof.point_e2,
            capsule.point_v,
            cfrag.point_v1,
            cfrag.proof.point_v2,
            params.u,
            cfrag.proof.kfrag_commitment,
            cfrag.proof.kfrag_pok,
        ]);

        let e1h = &cfrag.point_e1 * &h;
        let v1h = &cfrag.point_v1 * &h;
        let u1h = &u1 * &h;

        let z = cfrag.proof.signature;
        let ez = &capsule.point_e * &z;
        let vz = &capsule.point_v * &z;
        let uz = &u * &z;

        let precursor = cfrag.precursor;

        let kfrag_message = kfrag_signature_message(
            &cfrag.kfrag_id,
            &u1,
            &cfrag.precursor,
            Some(delegating_pk),
            Some(receiving_pk),
        );

        let kfrag_message_hash = digest_for_signing(&kfrag_message).finalize();

        let kfrag_signature_v = cfrag
            .proof
            .kfrag_signature
            .get_recovery_byte(verifying_pk, &kfrag_message)
            == 1;

        Self {
            e: capsule.point_e,
            ez,
            e1: cfrag.point_e1,
            e1h,
            e2: cfrag.proof.point_e2,
            v: capsule.point_v,
            vz,
            v1: cfrag.point_v1,
            v1h,
            v2: cfrag.proof.point_v2,
            uz,
            u1,
            u1h,
            u2,
            precursor,
            kfrag_validity_message_hash: kfrag_message_hash,
            kfrag_signature_v,
        }
    }
}

#[cfg(feature = "default-serialization")]
impl DefaultSerialize for ReencryptionEvidence {}

#[cfg(feature = "default-serialization")]
impl<'de> DefaultDeserialize<'de> for ReencryptionEvidence {}
