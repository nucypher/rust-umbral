//! This module contains hashing sequences with included domain separation tags
//! shared between different parts of the code.

use generic_array::GenericArray;

use crate::curve::{CurvePoint, CurveScalar};
use crate::hashing::{BytesDigest, BytesDigestOutputSize, ScalarDigest};
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

// TODO (#39): Ideally this should return a non-zero scalar.
// (when it does, the loop in `KeyFragFactory::new()` can be removed)
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

pub(crate) fn hash_metadata(bytes: &[u8]) -> GenericArray<u8, BytesDigestOutputSize> {
    BytesDigest::new_with_dst(b"METADATA")
        .chain_bytes(bytes)
        .finalize()
}
