use crate::capsule::Capsule;
use crate::curve::{point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurveScalar};
use crate::keys::{UmbralPublicKey, UmbralSignature};
use crate::kfrags::KFrag;
use crate::random_oracles::hash_to_scalar;

use generic_array::sequence::Concat;

pub struct CorrectnessProof {
    point_e2: CurvePoint,
    point_v2: CurvePoint,
    point_kfrag_commitment: CurvePoint,
    point_kfrag_pok: CurvePoint,
    bn_sig: CurveScalar,
    kfrag_signature: UmbralSignature,

    // TODO: (for @tux and @dnunez): originally it was a bytestring.
    // In heapless mode I'd have to make this struct, and all that depends on it
    // generic on the metadata size, and that's just too cumbersome.
    // Instead I'm hashing it to a scalar. Hope it's ok.
    metadata: CurveScalar,
}

impl CorrectnessProof {
    pub fn from_kfrag_and_cfrag(
        capsule: &Capsule,
        kfrag: &KFrag,
        cfrag_e1: &CurvePoint,
        cfrag_v1: &CurvePoint,
        metadata: &CurveScalar,
    ) -> Self {
        let params = capsule.params;

        // Check correctness of original ciphertext
        // TODO: should be already verified?
        //if not capsule.verify():
        //    raise capsule.NotValid("Capsule verification failed.")

        let rk = kfrag.bn_key;
        let t = random_scalar();

        // Here are the formulaic constituents shared with `verify_correctness`.

        let e = capsule.point_e;
        let v = capsule.point_v;

        let e1 = cfrag_e1;
        let v1 = cfrag_v1;

        let u = params.u;
        let u1 = kfrag.proof.point_commitment;

        let e2 = &e * &t;
        let v2 = &v * &t;
        let u2 = &u * &t;

        let hash_input = [e, *e1, e2, v, *v1, v2, u, u1, u2];

        // TODO: original uses ExtendedKeccak here
        let h = hash_to_scalar(&hash_input, Some(&scalar_to_bytes(metadata)));

        ////////

        let z3 = &t + &rk * &h;

        Self {
            point_e2: e2,
            point_v2: v2,
            point_kfrag_commitment: u1,
            point_kfrag_pok: u2,
            bn_sig: z3,
            kfrag_signature: kfrag.proof.signature_for_bob(),
            metadata: *metadata,
        }
    }
}

pub struct CapsuleFrag {
    pub point_e1: CurvePoint,
    pub point_v1: CurvePoint,
    pub kfrag_id: CurveScalar,
    pub point_precursor: CurvePoint,
    pub proof: CorrectnessProof,
}

impl CapsuleFrag {
    pub fn from_kfrag(capsule: &Capsule, kfrag: &KFrag, metadata: Option<&[u8]>) -> Self {
        let rk = kfrag.bn_key;
        let e1 = &capsule.point_e * &rk;
        let v1 = &capsule.point_v * &rk;
        let metadata_scalar = match metadata {
            Some(s) => hash_to_scalar(&[], Some(s)),
            None => CurveScalar::default(),
        };
        let proof =
            CorrectnessProof::from_kfrag_and_cfrag(&capsule, &kfrag, &e1, &v1, &metadata_scalar);

        Self {
            point_e1: e1,
            point_v1: v1,
            kfrag_id: kfrag.id,
            point_precursor: kfrag.point_precursor,
            proof: proof,
        }
    }

    pub fn verify_correctness(
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
        let u1 = self.proof.point_kfrag_commitment;

        let e2 = self.proof.point_e2;
        let v2 = self.proof.point_v2;
        let u2 = self.proof.point_kfrag_pok;

        let hash_input = [e, e1, e2, v, v1, v2, u, u1, u2];

        // TODO: original uses ExtendedKeccak here
        let h = hash_to_scalar(&hash_input, Some(&self.proof.metadata.to_bytes()));

        ///////

        let precursor = self.point_precursor;
        let kfrag_id = self.kfrag_id;

        // TODO: hide this in a special mutable object associated with Signer?
        let kfrag_validity_message = scalar_to_bytes(&kfrag_id)
            .concat(delegating_pubkey.to_bytes())
            .concat(receiving_pubkey.to_bytes())
            .concat(point_to_bytes(&u1))
            .concat(point_to_bytes(&precursor));

        let valid_kfrag_signature =
            signing_pubkey.verify(&kfrag_validity_message, &self.proof.kfrag_signature);

        let z3 = self.proof.bn_sig;
        let correct_reencryption_of_e = &e * &z3 == &e2 + &(&e1 * &h);
        let correct_reencryption_of_v = &v * &z3 == &v2 + &(&v1 * &h);
        let correct_rk_commitment = &u * &z3 == &u2 + &(&u1 * &h);

        valid_kfrag_signature
            & correct_reencryption_of_e
            & correct_reencryption_of_v
            & correct_rk_commitment
    }
}
