#![no_std]

#[cfg(feature = "std")]
extern crate std;

mod capsule;
mod capsule_frag;
mod constants;
mod curve;
mod dem;
mod key_frag;
mod keys;
mod params;
mod pre;
mod random_oracles;

#[cfg(feature = "std")]
pub use pre::{decrypt_original, decrypt_reencrypted, encrypt};

#[cfg(feature = "std")]
pub use key_frag::generate_kfrags;

pub use key_frag::KeyFragFactoryHeapless;
pub use keys::UmbralPrivateKey;
pub use params::UmbralParameters;
pub use pre::{decrypt_original_in_place, decrypt_reencrypted_in_place, encrypt_in_place};
