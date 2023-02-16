//! This module contains hashing sequences with included domain separation tags
//! shared between different parts of the code.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::curve::{CurvePoint, NonZeroCurveScalar};
use crate::hashing::ScalarDigest;
use crate::key_frag::KeyFragID;
use crate::keys::PublicKey;

// These imports are only used in docstrings.
#[cfg(docsrs)]
use crate::{Capsule, CapsuleFrag, Parameters, ReencryptionEvidence};

pub(crate) fn hash_to_polynomial_arg(
    precursor: &CurvePoint,
    pubkey: &CurvePoint,
    dh_point: &CurvePoint,
    kfrag_id: &KeyFragID,
) -> NonZeroCurveScalar {
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
) -> NonZeroCurveScalar {
    ScalarDigest::new_with_dst(b"SHARED_SECRET")
        .chain_point(precursor)
        .chain_point(pubkey)
        .chain_point(dh_point)
        .finalize()
}

pub(crate) fn hash_capsule_points(
    capsule_e: &CurvePoint,
    capsule_v: &CurvePoint,
) -> NonZeroCurveScalar {
    ScalarDigest::new_with_dst(b"CAPSULE_POINTS")
        .chain_point(capsule_e)
        .chain_point(capsule_v)
        .finalize()
}

/// Calculates the challenge scalar for the proof of reencryption.
///
/// Note: this function is only public for documenting purposes
/// (see [`ReencryptionEvidence`]).
///
/// Calculated as the SHA256 hash of the concatenation of
/// (the points are represented in the compressed form, 33 bytes each):
/// - `0x00000012` (4 bytes, the length of the DST)
/// - `b"CFRAG_VERIFICATION"` (18 bytes)
/// - `Capsule::e`
/// - `CapsuleFrag::e1`
/// - `CapsuleFrag::e2`
/// - `Capsule::v`
/// - `CapsuleFrag::v1`
/// - `CapsuleFrag::v2`
/// - [`Parameters::u`]
/// - `CapsuleFrag::u1`
/// - `CapsuleFrag::u2`
///
/// The hash (32 bytes) is then treated as the big-endian representation of an integer,
/// and converted to a non-zero curve scalar by taking the modulo of `p - 1` and adding 1,
/// where `p` is the secp256k1 order.
///
/// The points mentioned above are the same as in the return values of
/// [`Capsule::to_bytes_simple`] and [`CapsuleFrag::to_bytes_simple`].
#[allow(clippy::too_many_arguments)]
pub fn hash_to_cfrag_verification(
    e: &CurvePoint,
    e1: &CurvePoint,
    e2: &CurvePoint,
    v: &CurvePoint,
    v1: &CurvePoint,
    v2: &CurvePoint,
    u: &CurvePoint,
    u1: &CurvePoint,
    u2: &CurvePoint,
) -> NonZeroCurveScalar {
    ScalarDigest::new_with_dst(b"CFRAG_VERIFICATION")
        .chain_point(e)
        .chain_point(e1)
        .chain_point(e2)
        .chain_point(v)
        .chain_point(v1)
        .chain_point(v2)
        .chain_point(u)
        .chain_point(u1)
        .chain_point(u2)
        .finalize()
}

fn bool_to_array(val: bool) -> [u8; 1] {
    if val {
        [1u8]
    } else {
        [0u8]
    }
}

pub(crate) fn kfrag_signature_message(
    kfrag_id: &KeyFragID,
    commitment: &CurvePoint,
    precursor: &CurvePoint,
    maybe_delegating_pk: Option<&PublicKey>,
    maybe_receiving_pk: Option<&PublicKey>,
) -> Box<[u8]> {
    let mut result = Vec::<u8>::new();

    result.extend_from_slice(kfrag_id.as_ref());
    result.extend_from_slice(&commitment.to_compressed_array());
    result.extend_from_slice(&precursor.to_compressed_array());

    match maybe_delegating_pk {
        Some(delegating_pk) => {
            result.extend_from_slice(&bool_to_array(true));
            result.extend_from_slice(&delegating_pk.to_point().to_compressed_array())
        }
        None => result.extend_from_slice(&bool_to_array(false)),
    };

    match maybe_receiving_pk {
        Some(receiving_pk) => {
            result.extend_from_slice(&bool_to_array(true));
            result.extend_from_slice(&receiving_pk.to_point().to_compressed_array())
        }
        None => result.extend_from_slice(&bool_to_array(false)),
    };

    result.into_boxed_slice()
}
