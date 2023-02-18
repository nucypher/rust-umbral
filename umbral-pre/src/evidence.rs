use alloc::string::{String, ToString};

use sha2::digest::Digest;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::curve::CurvePoint;
use crate::hashing::BackendDigestOutput;
use crate::hashing_ds::{hash_to_cfrag_verification, kfrag_signature_message};
use crate::keys::digest_for_signing;
use crate::params::Parameters;
use crate::{Capsule, PublicKey, VerifiedCapsuleFrag};

// These imports are only used in docstrings.
#[cfg(docsrs)]
use crate::CapsuleFrag;

#[cfg(feature = "default-serialization")]
use crate::{DefaultDeserialize, DefaultSerialize};

/// A collection of data to prove the validity of reencryption.
///
/// In combination with the return values of [`Capsule::to_bytes_simple`] and
/// [`CapsuleFrag::to_bytes_simple`], it can be used to perform the following checks:
///
/// 1. Check that Alice's verifying key (or the corresponding Ethereum address)
///    can be derived from `CapsuleFrag::kfrag_signature`, `kfrag_validity_message_hash`, and
///    the recovery byte `kfrag_signature_v` (`true` corresponds to `0x01` and `false` to `0x00`).
///
/// 2. Zero-knowledge verification (performed in [`CapsuleFrag::verify`]):
///    - `z * e == h * e1 + e2` (correct re-encryption of `e`);
///    - `z * v == h * v1 + v2` (correct re-encryption of `v`);
///    - `z * u == h * u1 + u2` (correct re-encryption key commitment).
///
/// Here `z == CapsuleFrag::signature`, `u` is the constant scheme parameter
/// (can be hardcoded in the contract performing the check, see [`Parameters::u`]
/// for the value), `e` and `v` are from [`Capsule::to_bytes_simple`],
/// and `e1`, `e2`, `v1`, `v2`, `u1`, `u2` are from [`CapsuleFrag::to_bytes_simple`].
///
/// The serialized capsule and cfrag have these points in the compressed form, so this struct
/// provides both coordinates to let the user avoid uncompressing the point.
/// Instead one can just check that the the `y` coordinate corresponds to the sign
/// in the compressed point, and that the whole point is on the curve.
///
/// `h` is the challenge scalar, see [`hash_to_cfrag_verification`]
/// for the details on how to reproduce its calculation.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReencryptionEvidence {
    /// Same as `e` in [`Capsule::to_bytes_simple`].
    pub e: CurvePoint,
    /// Precalculated `z * e`, where `z == CapsuleFrag::signature`
    /// in [`CapsuleFrag::to_bytes_simple`].
    pub ez: CurvePoint,
    /// Same as `e1` in [`CapsuleFrag::to_bytes_simple`].
    pub e1: CurvePoint,
    /// Precalculated `h * e1`, where `h` is obtained from [`hash_to_cfrag_verification`].
    pub e1h: CurvePoint,
    /// Same as `e2` in [`CapsuleFrag::to_bytes_simple`].
    pub e2: CurvePoint,
    /// Same as `v` in [`Capsule::to_bytes_simple`].
    pub v: CurvePoint,
    /// Precalculated `z * v`, where `z == CapsuleFrag::signature`
    /// in [`CapsuleFrag::to_bytes_simple`].
    pub vz: CurvePoint,
    /// Same as `v1` in [`CapsuleFrag::to_bytes_simple`].
    pub v1: CurvePoint,
    /// Precalculated `h * v1`, where `h` is obtained from [`hash_to_cfrag_verification`].
    pub v1h: CurvePoint,
    /// Same as `v2` in [`CapsuleFrag::to_bytes_simple`].
    pub v2: CurvePoint,
    /// Precalculated `z * u`, where `z == CapsuleFrag::signature`
    /// in [`CapsuleFrag::to_bytes_simple`], and `u` is [`Parameters::u`].
    pub uz: CurvePoint,
    /// Same as `u1` in [`CapsuleFrag::to_bytes_simple`].
    pub u1: CurvePoint,
    /// Precalculated `h * u1`, where `h` is obtained from [`hash_to_cfrag_verification`].
    pub u1h: CurvePoint,
    /// Same as `u2` in [`CapsuleFrag::to_bytes_simple`].
    pub u2: CurvePoint,
    /// The hashed message used to create `kfrag_signature` in
    /// [`CapsuleFrag::to_bytes_simple`].
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_bytes::as_hex"))]
    pub kfrag_validity_message_hash: BackendDigestOutput,
    /// The recovery byte corresponding to `kfrag_signature` in [`CapsuleFrag::to_bytes_simple`]
    /// (`true` corresponds to `0x01` and `false` to `0x00`).
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
    ) -> Result<Self, String> {
        let params = Parameters::new();

        let cfrag = vcfrag.clone().unverify();

        let u = params.u;
        let u1 = cfrag.proof.kfrag_commitment;
        let u2 = cfrag.proof.kfrag_pok;

        let h = hash_to_cfrag_verification(
            &capsule.point_e,
            &cfrag.point_e1,
            &cfrag.proof.point_e2,
            &capsule.point_v,
            &cfrag.point_v1,
            &cfrag.proof.point_v2,
            &params.u,
            &cfrag.proof.kfrag_commitment,
            &cfrag.proof.kfrag_pok,
        );

        let e1h = &cfrag.point_e1 * &h;
        let v1h = &cfrag.point_v1 * &h;
        let u1h = &u1 * &h;

        let z = cfrag.proof.signature;
        let ez = &capsule.point_e * &z;
        let vz = &capsule.point_v * &z;
        let uz = &u * &z;

        let kfrag_message = kfrag_signature_message(
            &cfrag.kfrag_id,
            &u1,
            &cfrag.precursor,
            Some(delegating_pk),
            Some(receiving_pk),
        );

        let kfrag_message_hash = digest_for_signing(&kfrag_message).finalize();

        let recovery_id = cfrag
            .proof
            .kfrag_signature
            .get_recovery_id(verifying_pk, &kfrag_message)
            .ok_or_else(|| {
                "Could not find the recovery ID for the kfrag signature: mismatched verifying key?"
                    .to_string()
            })?;

        // Note that there is also `is_x_reduced`, but it is currently not handled by `ecdsa` crate.
        let kfrag_signature_v = recovery_id.is_y_odd();

        // TODO: we can also expose `precursor` here to allow the user to calculate
        // `kfrag_message_hash` by themselves. Is it necessary?

        Ok(Self {
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
            kfrag_validity_message_hash: kfrag_message_hash,
            kfrag_signature_v,
        })
    }
}

#[cfg(feature = "default-serialization")]
impl DefaultSerialize for ReencryptionEvidence {}

#[cfg(feature = "default-serialization")]
impl<'de> DefaultDeserialize<'de> for ReencryptionEvidence {}

#[cfg(test)]
mod tests {
    use super::ReencryptionEvidence;
    use crate::{
        curve::CurveScalar, encrypt, generate_kfrags, hash_to_cfrag_verification, reencrypt,
        Parameters, PublicKey, RecoverableSignature, SecretKey, Signature, Signer,
    };

    fn assert_eq_byte_refs(x: &(impl AsRef<[u8]> + ?Sized), y: &(impl AsRef<[u8]> + ?Sized)) {
        assert_eq!(x.as_ref(), y.as_ref());
    }

    #[test]
    fn contract() {
        let threshold: usize = 2;
        let num_frags: usize = threshold + 1;

        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let signer = Signer::new(SecretKey::random());
        let verifying_pk = signer.verifying_key();

        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        let vkfrags = generate_kfrags(
            &delegating_sk,
            &receiving_pk,
            &signer,
            threshold,
            num_frags,
            true,
            true,
        );

        let vcfrag = reencrypt(&capsule, vkfrags[0].clone());

        let evidence = ReencryptionEvidence::new(
            &capsule,
            &vcfrag,
            &verifying_pk,
            &delegating_pk,
            &receiving_pk,
        )
        .unwrap();

        let capsule_bytes = capsule.to_bytes_simple();
        let cfrag_bytes = vcfrag.to_bytes_simple();

        // Recover and check components
        assert_eq_byte_refs(&capsule_bytes[0..33], &evidence.e.to_compressed_array());
        assert_eq_byte_refs(&capsule_bytes[33..66], &evidence.v.to_compressed_array());

        assert_eq_byte_refs(&cfrag_bytes[0..33], &evidence.e1.to_compressed_array());
        assert_eq_byte_refs(&cfrag_bytes[33..66], &evidence.v1.to_compressed_array());
        assert_eq_byte_refs(&cfrag_bytes[131..164], &evidence.e2.to_compressed_array());
        assert_eq_byte_refs(&cfrag_bytes[164..197], &evidence.v2.to_compressed_array());
        assert_eq_byte_refs(&cfrag_bytes[197..230], &evidence.u1.to_compressed_array());
        assert_eq_byte_refs(&cfrag_bytes[230..263], &evidence.u2.to_compressed_array());

        let z = CurveScalar::try_from_bytes(&cfrag_bytes[263..(263 + 32)]).unwrap();

        let sig = Signature::try_from_be_bytes(&cfrag_bytes[295..(295 + 64)]).unwrap();
        let rsig = RecoverableSignature::from_normalized(sig, evidence.kfrag_signature_v);

        // Check that the Alice's verifying key can be recovered from the signature
        let vkey =
            PublicKey::recover_from_prehash(&evidence.kfrag_validity_message_hash, &rsig).unwrap();
        assert_eq!(vkey, verifying_pk);

        // Check the ZKP identities

        let params = Parameters::new();

        let h = hash_to_cfrag_verification(
            &evidence.e,
            &evidence.e1,
            &evidence.e2,
            &evidence.v,
            &evidence.v1,
            &evidence.v2,
            &params.u,
            &evidence.u1,
            &evidence.u2,
        );

        assert_eq!(&evidence.e * &z, &(&evidence.e1 * &h) + &evidence.e2);
        assert_eq!(&evidence.v * &z, &(&evidence.v1 * &h) + &evidence.v2);
        assert_eq!(&params.u * &z, &(&evidence.u1 * &h) + &evidence.u2);
    }
}
