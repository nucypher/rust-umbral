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
mod utils;

#[cfg(feature = "std")]
pub use pre::{decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags};

pub use pre::{
    decrypt_original_in_place, decrypt_reencrypted_in_place, encrypt_in_place, reencrypt,
    KFragFactory,
};

pub use keys::UmbralPrivateKey;
pub use params::UmbralParameters;
