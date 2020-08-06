#![no_std]

#[cfg(feature = "std")]
extern crate std;

mod capsule;
mod cfrags;
mod constants;
mod curve;
mod dem;
mod keys;
mod kfrags;
mod params;
mod pre;
mod random_oracles;

#[cfg(feature = "std")]
pub use pre::{decrypt_original, decrypt_reencrypted, encrypt};

#[cfg(feature = "std")]
pub use kfrags::generate_kfrags;

pub use keys::UmbralPrivateKey;
pub use kfrags::KFragFactoryHeapless;
pub use params::UmbralParameters;
pub use pre::{decrypt_original_in_place, decrypt_reencrypted_in_place, encrypt_in_place};
