#![no_std]

extern crate alloc;

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
mod traits;

pub use key_frag::generate_kfrags;
pub use pre::{decrypt_original, decrypt_reencrypted, encrypt};

pub use capsule::{Capsule, PreparedCapsule};
pub use capsule_frag::CapsuleFrag;
pub use curve::{UmbralPublicKey, UmbralSecretKey};
pub use key_frag::KeyFrag;
pub use params::UmbralParameters;
pub use traits::SerializableToArray;
