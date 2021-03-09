use crate::capsule::Capsule;
use crate::curve::{CurvePoint, CurveScalar};
use crate::curve::{PublicKey, Signature};
use crate::hashing::{BytesDigestOutputSize, ScalarDigest, SignatureDigest};
use crate::hashing_ds::hash_metadata;
use crate::key_frag::{KeyFrag, KeyFragID};
use crate::traits::SerializableToArray;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::op;

type HashedMetadataSize = BytesDigestOutputSize;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct HashedMetadata(GenericArray<u8, HashedMetadataSize>);

impl HashedMetadata {
    fn new(maybe_metadata: Option<&[u8]>) -> Self {
        let metadata = maybe_metadata.unwrap_or(b"");
        Self(hash_metadata(metadata))
    }
}

impl AsRef<[u8]> for HashedMetadata {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SerializableToArray for HashedMetadata {
    type Size = HashedMetadataSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        Some(Self(*arr))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CapsuleFragProof {
    point_e2: CurvePoint,
    point_v2: CurvePoint,
    kfrag_commitment: CurvePoint,
    kfrag_pok: CurvePoint,
    signature: CurveScalar,
    kfrag_signature: Signature,
    metadata: HashedMetadata,
}

type PointSize = <CurvePoint as SerializableToArray>::Size;
type ScalarSize = <CurveScalar as SerializableToArray>::Size;
type SignatureSize = <Signature as SerializableToArray>::Size;
type CapsuleFragProofSize =
    op!(PointSize + PointSize + PointSize + PointSize + ScalarSize + SignatureSize + ScalarSize);

impl SerializableToArray for CapsuleFragProof {
    type Size = CapsuleFragProofSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.point_e2
            .to_array()
            .concat(self.point_v2.to_array())
            .concat(self.kfrag_commitment.to_array())
            .concat(self.kfrag_pok.to_array())
            .concat(self.signature.to_array())
            .concat(self.kfrag_signature.to_array())
            .concat(self.metadata.to_array())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let (point_e2, rest) = CurvePoint::take(*arr)?;
        let (point_v2, rest) = CurvePoint::take(rest)?;
        let (kfrag_commitment, rest) = CurvePoint::take(rest)?;
        let (kfrag_pok, rest) = CurvePoint::take(rest)?;
        let (signature, rest) = CurveScalar::take(rest)?;
        let (kfrag_signature, rest) = Signature::take(rest)?;
        let metadata = HashedMetadata::take_last(rest)?;
        Some(Self {
            point_e2,
            point_v2,
            kfrag_commitment,
            kfrag_pok,
            signature,
            kfrag_signature,
            metadata,
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
        metadata: &HashedMetadata,
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

        let h = ScalarDigest::new()
            .chain_points(&[e, *e1, e2, v, *v1, v2, u, u1, u2])
            .chain_bytes(metadata)
            .finalize();

        ////////

        let z3 = &t + &(&rk * &h);

        Self {
            point_e2: e2,
            point_v2: v2,
            kfrag_commitment: u1,
            kfrag_pok: u2,
            signature: z3,
            kfrag_signature: kfrag.proof.signature_for_bob(),
            metadata: *metadata,
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

type CapsuleFragSize = op!(PointSize + PointSize + ScalarSize + PointSize + CapsuleFragProofSize);

impl SerializableToArray for CapsuleFrag {
    type Size = CapsuleFragSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.point_e1
            .to_array()
            .concat(self.point_v1.to_array())
            .concat(self.kfrag_id.to_array())
            .concat(self.precursor.to_array())
            .concat(self.proof.to_array())
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let (point_e1, rest) = CurvePoint::take(*arr)?;
        let (point_v1, rest) = CurvePoint::take(rest)?;
        let (kfrag_id, rest) = KeyFragID::take(rest)?;
        let (precursor, rest) = CurvePoint::take(rest)?;
        let proof = CapsuleFragProof::take_last(rest)?;
        Some(Self {
            point_e1,
            point_v1,
            kfrag_id,
            precursor,
            proof,
        })
    }
}

impl CapsuleFrag {
    pub(crate) fn reencrypted(
        capsule: &Capsule,
        kfrag: &KeyFrag,
        maybe_metadata: Option<&[u8]>,
    ) -> Self {
        let rk = kfrag.key;
        let e1 = &capsule.point_e * &rk;
        let v1 = &capsule.point_v * &rk;
        let metadata = HashedMetadata::new(maybe_metadata);
        let proof = CapsuleFragProof::from_kfrag_and_cfrag(&capsule, &kfrag, &e1, &v1, &metadata);

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
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
        signing_pk: &PublicKey,
    ) -> bool {
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

        let h = ScalarDigest::new()
            .chain_points(&[e, e1, e2, v, v1, v2, u, u1, u2])
            .chain_bytes(&self.proof.metadata)
            .finalize();

        ///////

        let precursor = self.precursor;
        let kfrag_id = self.kfrag_id;

        let valid_kfrag_signature = SignatureDigest::new()
            .chain_bytes(&kfrag_id)
            .chain_pubkey(delegating_pk)
            .chain_pubkey(receiving_pk)
            .chain_point(&u1)
            .chain_point(&precursor)
            .verify(signing_pk, &self.proof.kfrag_signature);

        let z3 = self.proof.signature;
        let correct_reencryption_of_e = &e * &z3 == &e2 + &(&e1 * &h);
        let correct_reencryption_of_v = &v * &z3 == &v2 + &(&v1 * &h);
        let correct_rk_commitment = &u * &z3 == &u2 + &(&u1 * &h);

        valid_kfrag_signature
            & correct_reencryption_of_e
            & correct_reencryption_of_v
            & correct_rk_commitment
    }
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use super::CapsuleFrag;
    use crate::{
        encrypt, generate_kfrags, reencrypt, Capsule, Parameters, PublicKey, SecretKey,
        SerializableToArray,
    };

    fn prepare_cfrags() -> (PublicKey, PublicKey, PublicKey, Capsule, Box<[CapsuleFrag]>) {
        let params = Parameters::new();

        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let signing_pk = PublicKey::from_secret_key(&signing_sk);

        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&params, &delegating_pk, plaintext).unwrap();

        let kfrags = generate_kfrags(
            &params,
            &delegating_sk,
            &receiving_pk,
            &signing_sk,
            2,
            3,
            true,
            true,
        );

        let cfrags: Vec<CapsuleFrag> = kfrags
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag, None))
            .collect();

        (
            delegating_pk,
            receiving_pk,
            signing_pk,
            capsule,
            cfrags.into_boxed_slice(),
        )
    }

    #[test]
    fn test_serialize() {
        let (_, _, _, _, cfrags) = prepare_cfrags();
        let cfrag_arr = cfrags[0].to_array();
        let cfrag_back = CapsuleFrag::from_array(&cfrag_arr).unwrap();
        assert_eq!(cfrags[0], cfrag_back);
    }

    #[test]
    fn test_verify() {
        let (delegating_pk, receiving_pk, signing_pk, capsule, cfrags) = prepare_cfrags();
        assert!(cfrags.iter().all(|cfrag| cfrag.verify(
            &capsule,
            &delegating_pk,
            &receiving_pk,
            &signing_pk,
        )));
    }
}
