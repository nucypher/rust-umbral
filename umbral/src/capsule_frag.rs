use crate::capsule::Capsule;
use crate::curve::{CurvePoint, CurveScalar};
use crate::curve::{UmbralPublicKey, UmbralSignature};
use crate::hashing::{ScalarDigest, SignatureDigest};
use crate::key_frag::KeyFrag;
use crate::traits::SerializableToArray;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::op;

pub struct CapsuleFragProof {
    point_e2: CurvePoint,
    point_v2: CurvePoint,
    kfrag_commitment: CurvePoint,
    kfrag_pok: CurvePoint,
    signature: CurveScalar,
    kfrag_signature: UmbralSignature,

    // TODO: (for @tux and @dnunez): originally it was a bytestring.
    // In heapless mode I'd have to make this struct, and all that depends on it
    // generic on the metadata size, and that's just too cumbersome.
    // Instead I'm hashing it to a scalar. Hope it's ok.
    metadata: CurveScalar,
}

type PointSize = <CurvePoint as SerializableToArray>::Size;
type ScalarSize = <CurveScalar as SerializableToArray>::Size;
type SignatureSize = <UmbralSignature as SerializableToArray>::Size;
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
        let (kfrag_signature, rest) = UmbralSignature::take(rest)?;
        let metadata = CurveScalar::take_last(rest)?;
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
        metadata: &CurveScalar,
    ) -> Self {
        let params = capsule.params;

        let rk = kfrag.key;
        let t = CurveScalar::random_nonzero();

        // Here are the formulaic constituents shared with `verify_correctness`.

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
            .chain_scalar(metadata)
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

pub struct CapsuleFrag {
    pub(crate) point_e1: CurvePoint,
    pub(crate) point_v1: CurvePoint,
    pub(crate) kfrag_id: CurveScalar,
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
        let (kfrag_id, rest) = CurveScalar::take(rest)?;
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
    pub fn from_kfrag(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<&[u8]>) -> Self {
        let rk = kfrag.key;
        let e1 = &capsule.point_e * &rk;
        let v1 = &capsule.point_v * &rk;
        let metadata_scalar = match metadata {
            // TODO: why do we hash scalar to a scalar here?
            Some(s) => ScalarDigest::new().chain_bytes(s).finalize(),
            None => CurveScalar::default(),
        };
        let proof =
            CapsuleFragProof::from_kfrag_and_cfrag(&capsule, &kfrag, &e1, &v1, &metadata_scalar);

        Self {
            point_e1: e1,
            point_v1: v1,
            kfrag_id: kfrag.id,
            precursor: kfrag.precursor,
            proof,
        }
    }

    pub(crate) fn verify(
        &self,
        capsule: &Capsule,
        delegating_pubkey: &UmbralPublicKey,
        receiving_pubkey: &UmbralPublicKey,
        signing_pubkey: &UmbralPublicKey,
    ) -> bool {
        let params = capsule.params;

        // TODO: Here are the formulaic constituents shared with `prove_correctness`.

        let e = capsule.point_e;
        let v = capsule.point_v;

        let e1 = self.point_e1;
        let v1 = self.point_v1;

        let u = params.u;
        let u1 = self.proof.kfrag_commitment;

        let e2 = self.proof.point_e2;
        let v2 = self.proof.point_v2;
        let u2 = self.proof.kfrag_pok;

        // TODO: original uses ExtendedKeccak here
        let h = ScalarDigest::new()
            .chain_points(&[e, e1, e2, v, v1, v2, u, u1, u2])
            .chain_scalar(&self.proof.metadata)
            .finalize();

        ///////

        let precursor = self.precursor;
        let kfrag_id = self.kfrag_id;

        let valid_kfrag_signature = SignatureDigest::new()
            .chain_scalar(&kfrag_id)
            .chain_pubkey(delegating_pubkey)
            .chain_pubkey(receiving_pubkey)
            .chain_point(&u1)
            .chain_point(&precursor)
            .verify(signing_pubkey, &self.proof.kfrag_signature);

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
