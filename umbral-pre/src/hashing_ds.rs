//! This module contains hashing sequences with included domain separation tags
//! shared between different parts of the code.

use crate::curve::{CurvePoint, CurveScalar, PublicKey};
use crate::hashing::{ScalarDigest, SignatureDigest};
use crate::key_frag::KeyFragID;

// TODO (#39): Ideally this should return a non-zero scalar.
pub(crate) fn hash_to_polynomial_arg(
    precursor: &CurvePoint,
    pubkey: &CurvePoint,
    dh_point: &CurvePoint,
    kfrag_id: &KeyFragID,
) -> CurveScalar {
    ScalarDigest::new_with_dst(b"POLYNOMIAL_ARG")
        .chain_point(precursor)
        .chain_point(pubkey)
        .chain_point(dh_point)
        .chain_bytes(kfrag_id)
        .finalize()
}

pub(crate) fn hash_to_shared_secret(
    precursor: &CurvePoint,
    pubkey: &CurvePoint,
    dh_point: &CurvePoint,
) -> CurveScalar {
    ScalarDigest::new_with_dst(b"SHARED_SECRET")
        .chain_point(precursor)
        .chain_point(pubkey)
        .chain_point(dh_point)
        .finalize()
}

pub(crate) fn hash_capsule_points(capsule_e: &CurvePoint, capsule_v: &CurvePoint) -> CurveScalar {
    ScalarDigest::new_with_dst(b"CAPSULE_POINTS")
        .chain_point(capsule_e)
        .chain_point(capsule_v)
        .finalize()
}

pub(crate) fn hash_to_cfrag_verification(
    points: &[CurvePoint],
    metadata: Option<&[u8]>,
) -> CurveScalar {
    let digest = ScalarDigest::new_with_dst(b"CFRAG_VERIFICATION").chain_points(points);

    let digest = match metadata {
        Some(s) => digest.chain_bytes(s),
        None => digest,
    };

    digest.finalize()
}

pub(crate) fn hash_to_cfrag_signature(
    kfrag_id: &KeyFragID,
    commitment: &CurvePoint,
    precursor: &CurvePoint,
    maybe_delegating_pk: Option<&PublicKey>,
    maybe_receiving_pk: Option<&PublicKey>,
) -> SignatureDigest {
    let digest = SignatureDigest::new_with_dst(b"CFRAG_SIGNATURE")
        .chain_bytes(kfrag_id)
        .chain_point(commitment)
        .chain_point(precursor);

    let digest = match maybe_delegating_pk {
        Some(delegating_pk) => digest.chain_bool(true).chain_pubkey(delegating_pk),
        None => digest.chain_bool(false),
    };

    #[allow(clippy::let_and_return)]
    let digest = match maybe_receiving_pk {
        Some(receiving_pk) => digest.chain_bool(true).chain_pubkey(receiving_pk),
        None => digest.chain_bool(false),
    };

    digest
}
