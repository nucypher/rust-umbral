//! `umbral-pre` is the Rust implementation of the [Umbral][umbral]
//! threshold proxy re-encryption scheme.
//!
//! Using `umbral-pre`, Alice (the data owner) can delegate decryption rights to Bob
//! for any ciphertext intended to her, through a re-encryption process
//! performed by a set of semi-trusted proxies or Ursulas.
//! When a threshold of these proxies participate by performing re-encryption,
//! Bob is able to combine these independent re-encryptions and decrypt the original message
//! using his private key.
//!
//! ## Available feature flags
//!
//! * `default-rng` - adds methods that use the system RNG (default).
//! * `default-serialization` - adds methods for default binary serialization
//!    that matches the serialization in the bindings.
//!    MessagePack, `serde`-based.
//! * `serde` - implements `serde`-based serialization and deserialization.
//! * `bindings-python` - adds a `bindings_python` submodule allowing dependent crates
//!        to use and re-export some of the Python-wrapped Umbral types.
//! * `bindings-wasm` - adds a `bindings_wasm` submodule allowing dependent crates
//!        to use and re-export some of the WASM-wrapped Umbral types.
//!
//! # Usage
//!
//! ```
//! use umbral_pre::*;
//!
//! // As in any public-key cryptosystem, users need a pair of public and private keys.
//! // Additionally, users that delegate access to their data (like Alice, in this example)
//! // need a signing keypair.
//!
//! // Key Generation (on Alice's side)
//! let alice_sk = SecretKey::random();
//! let alice_pk = alice_sk.public_key();
//! let signer = Signer::new(SecretKey::random());
//! let verifying_pk = signer.verifying_key();
//!
//! // Key Generation (on Bob's side)
//! let bob_sk = SecretKey::random();
//! let bob_pk = bob_sk.public_key();
//!
//! // Now let's encrypt data with Alice's public key.
//! // Invocation of `encrypt()` returns both the ciphertext and a capsule.
//! // Note that anyone with Alice's public key can perform this operation.
//!
//! let plaintext = b"peace at dawn";
//! let (capsule, ciphertext) = encrypt(&alice_pk, plaintext).unwrap();
//!
//! // Since data was encrypted with Alice's public key, Alice can open the capsule
//! // and decrypt the ciphertext with her private key.
//!
//! let plaintext_alice = decrypt_original(&alice_sk, &capsule, &ciphertext).unwrap();
//! assert_eq!(&plaintext_alice as &[u8], plaintext);
//!
//! // When Alice wants to grant Bob access to open her encrypted messages,
//! // she creates re-encryption key fragments, or "kfrags", which are then
//! // sent to `shares` proxies or Ursulas.
//!
//! let shares = 3; // how many fragments to create
//! let threshold = 2; // how many should be enough to decrypt
//! let verified_kfrags = generate_kfrags(&alice_sk, &bob_pk, &signer, threshold, shares, true, true);
//!
//! // Bob asks several Ursulas to re-encrypt the capsule so he can open it.
//! // Each Ursula performs re-encryption on the capsule using the kfrag provided by Alice,
//! // obtaining this way a "capsule fragment", or cfrag.
//!
//! // Simulate network transfer
//! let kfrag0 = verified_kfrags[0].clone().unverify();
//! let kfrag1 = verified_kfrags[1].clone().unverify();
//!
//! // Bob collects the resulting cfrags from several Ursulas.
//! // Bob must gather at least `threshold` cfrags in order to open the capsule.
//!
//! // Ursulas must check that the received kfrags are valid
//! // and perform the reencryption
//!
//! // Ursula 0
//! let verified_kfrag0 = kfrag0.verify(&verifying_pk, Some(&alice_pk), Some(&bob_pk)).unwrap();
//! let verified_cfrag0 = reencrypt(&capsule, verified_kfrag0);
//!
//! // Ursula 1
//! let verified_kfrag1 = kfrag1.verify(&verifying_pk, Some(&alice_pk), Some(&bob_pk)).unwrap();
//! let verified_cfrag1 = reencrypt(&capsule, verified_kfrag1);
//!
//! // ...
//!
//! // Simulate network transfer
//! let cfrag0 = verified_cfrag0.clone().unverify();
//! let cfrag1 = verified_cfrag1.clone().unverify();
//!
//! // Finally, Bob opens the capsule by using at least `threshold` cfrags,
//! // and then decrypts the re-encrypted ciphertext.
//!
//! // Bob must check that cfrags are valid
//! let verified_cfrag0 = cfrag0
//!     .verify(&capsule, &verifying_pk, &alice_pk, &bob_pk)
//!     .unwrap();
//! let verified_cfrag1 = cfrag1
//!     .verify(&capsule, &verifying_pk, &alice_pk, &bob_pk)
//!     .unwrap();
//!
//! let plaintext_bob = decrypt_reencrypted(
//!     &bob_sk, &alice_pk, &capsule, [verified_cfrag0, verified_cfrag1], &ciphertext).unwrap();
//! assert_eq!(&plaintext_bob as &[u8], plaintext);
//! ```
//!
//! [umbral]: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

#![doc(html_root_url = "https://docs.rs/umbral-pre")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![no_std]
// Allows us to mark items in the documentation as gated under specific features.
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

#[cfg(feature = "bench-internals")]
pub mod bench; // Re-export some internals for benchmarks.

#[cfg(feature = "bindings-python")]
pub mod bindings_python;
#[cfg(feature = "bindings-wasm")]
pub mod bindings_wasm;

mod capsule;
mod capsule_frag;
mod curve;
mod dem;
mod evidence;
mod hashing;
mod hashing_ds;
mod key_frag;
mod keys;
mod params;
mod pre;
mod secret_box;
mod traits;

#[cfg(feature = "serde")]
pub mod serde_bytes;

pub use capsule::{Capsule, OpenReencryptedError};
pub use capsule_frag::{CapsuleFrag, CapsuleFragVerificationError, VerifiedCapsuleFrag};
pub use curve::CurvePoint;
pub use dem::{DecryptionError, EncryptionError};
pub use evidence::ReencryptionEvidence;
pub use hashing_ds::hash_to_cfrag_verification;
pub use key_frag::{KeyFrag, KeyFragVerificationError, VerifiedKeyFrag};
pub use keys::{PublicKey, RecoverableSignature, SecretKey, SecretKeyFactory, Signature, Signer};
pub use params::Parameters;
pub use pre::{
    decrypt_original, decrypt_reencrypted, encrypt_with_rng, generate_kfrags_with_rng,
    reencrypt_with_rng, ReencryptionError,
};
pub use secret_box::SecretBox;

#[cfg(feature = "default-rng")]
pub use pre::{encrypt, generate_kfrags, reencrypt};

#[cfg(feature = "default-serialization")]
pub use traits::{DefaultDeserialize, DefaultSerialize};
