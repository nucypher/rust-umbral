#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate typenum;

mod capsule;
mod capsule_frag;
mod constants;
mod curve;
mod dem;
mod hashing;
mod key_frag;
mod params;
mod pre;

#[cfg(feature = "std")]
pub use pre::{decrypt_original, decrypt_reencrypted, encrypt};

#[cfg(feature = "std")]
pub use key_frag::generate_kfrags;

pub use curve::{UmbralPublicKey, UmbralSecretKey};
pub use key_frag::KeyFragFactoryHeapless;
pub use params::UmbralParameters;
pub use pre::{decrypt_original_in_place, decrypt_reencrypted_in_place, encrypt_in_place};
