//! Rust benchmarks are located in an external module, and cannot access private functions.
//! This module re-exports some internals for the purposes of benchmarking.
//! Should not be used by regular users.

use rand_core::OsRng;

use crate::capsule::{Capsule, KeySeed, OpenReencryptedError};
use crate::capsule_frag::{CapsuleFrag, VerifiedCapsuleFrag};
use crate::keys::{PublicKey, SecretKey};
use crate::secret_box::SecretBox;

pub use crate::hashing::unsafe_hash_to_point;

/// Exported `Capsule::from_public_key()` for benchmark purposes.
pub fn capsule_from_public_key(delegating_pk: &PublicKey) -> (Capsule, SecretBox<KeySeed>) {
    Capsule::from_public_key(&mut OsRng, delegating_pk)
}

/// Exported `Capsule::open_original()` for benchmark purposes.
pub fn capsule_open_original(capsule: &Capsule, delegating_sk: &SecretKey) -> SecretBox<KeySeed> {
    capsule.open_original(delegating_sk)
}

/// Exported `Capsule::open_reencrypted()` for benchmark purposes.
pub fn capsule_open_reencrypted(
    capsule: &Capsule,
    receiving_sk: &SecretKey,
    delegating_pk: &PublicKey,
    cfrags: &[CapsuleFrag],
) -> Result<SecretBox<KeySeed>, OpenReencryptedError> {
    capsule.open_reencrypted(receiving_sk, delegating_pk, cfrags)
}

/// Extracts the internal [`CapsuleFrag`] from a [`VerifiedCapsuleFrag`].
pub fn get_cfrag(verified_cfrag: &VerifiedCapsuleFrag) -> &CapsuleFrag {
    &verified_cfrag.cfrag
}
