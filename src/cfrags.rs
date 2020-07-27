use crate::curve::{CurveScalar, CurvePoint, random_scalar};
use crate::kfrags::KFrag;
use crate::capsule::Capsule;
use crate::keys::UmbralSignature;
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
    point_e1: CurvePoint,
    point_v1: CurvePoint,
    kfrag_id: CurveScalar,
    point_precursor: CurvePoint,
    proof: CorrectnessProof,
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

}
