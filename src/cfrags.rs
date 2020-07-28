use crate::curve::{CurveScalar, CurvePoint, random_scalar, point_to_bytes, scalar_to_bytes};
use crate::kfrags::KFrag;
use crate::capsule::Capsule;
use crate::keys::{UmbralPublicKey, UmbralSignature};
use crate::random_oracles::hash_to_scalar;

pub struct CorrectnessProof {
    point_e2: CurvePoint,
    point_v2: CurvePoint,
    point_kfrag_commitment: CurvePoint,
    point_kfrag_pok: CurvePoint,
    bn_sig: CurveScalar,
    kfrag_signature: UmbralSignature,
    metadata: Vec<u8>
}

impl CorrectnessProof {

    pub fn from_kfrag_and_cfrag(
                   capsule: &Capsule,
                   kfrag: &KFrag,
                   cfrag_e1: &CurvePoint,
                   cfrag_v1: &CurvePoint,
                   metadata: Option<&[u8]>) -> Self {

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
        let u1 = kfrag.point_commitment;

        let e2 = &e * &t;
        let v2 = &v * &t;
        let u2 = &u * &t;

        let hash_input = [e, *e1, e2, v, *v1, v2, u, u1, u2];

        // TODO: original uses ExtendedKeccak here
        let h = hash_to_scalar(&hash_input, metadata);

        ////////

        let vec_metadata: Vec<u8> = match metadata {
            Some(s) => s.iter().copied().collect(),
            None => vec![]
        };

        let z3 = &t + &rk * &h;

        Self {
            point_e2: e2,
            point_v2: v2,
            point_kfrag_commitment: u1,
            point_kfrag_pok: u2,
            bn_sig: z3,
            kfrag_signature: kfrag.signature_for_bob.clone(),
            metadata: vec_metadata,
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
        let proof = CorrectnessProof::from_kfrag_and_cfrag(&capsule, &kfrag, &e1, &v1, metadata);

        Self {
            point_e1: e1,
            point_v1: v1,
            kfrag_id: kfrag.id,
            point_precursor: kfrag.point_precursor,
            proof: proof
        }
    }

    pub fn verify_correctness(&self, capsule: &Capsule, delegating_pubkey: &UmbralPublicKey,
            receiving_pubkey: &UmbralPublicKey, signing_pubkey: &UmbralPublicKey) -> bool {

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
        let h = hash_to_scalar(&hash_input, Some(&self.proof.metadata));

        ///////

        let precursor = self.point_precursor;
        let kfrag_id = self.kfrag_id;

        // TODO: hide this in a special mutable object associated with Signer?
        let kfrag_validity_message: Vec<u8> =
            scalar_to_bytes(&kfrag_id).iter()
            .chain(delegating_pubkey.to_bytes().iter())
            .chain(receiving_pubkey.to_bytes().iter())
            .chain(point_to_bytes(&u1).iter())
            .chain(point_to_bytes(&precursor).iter())
            .copied().collect();

        let valid_kfrag_signature = signing_pubkey.verify(&kfrag_validity_message, &self.proof.kfrag_signature);

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
