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
//! let alice_pk = PublicKey::from_secret_key(&alice_sk);
//! let signing_sk = SecretKey::random();
//! let signer = Signer::new(&signing_sk);
//! let verifying_pk = PublicKey::from_secret_key(&signing_sk);
//!
//! // Key Generation (on Bob's side)
//! let bob_sk = SecretKey::random();
//! let bob_pk = PublicKey::from_secret_key(&bob_sk);
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
//! // sent to `n` proxies or Ursulas.
//!
//! let n = 3; // how many fragments to create
//! let m = 2; // how many should be enough to decrypt
//! let kfrags = generate_kfrags(&alice_sk, &bob_pk, &signer, m, n, true, true);
//!
//! // Bob asks several Ursulas to re-encrypt the capsule so he can open it.
//! // Each Ursula performs re-encryption on the capsule using the kfrag provided by Alice,
//! // obtaining this way a "capsule fragment", or cfrag.
//!
//! // Bob collects the resulting cfrags from several Ursulas.
//! // Bob must gather at least `m` cfrags in order to open the capsule.
//!
//! // Ursulas can optionally check that the received kfrags are valid
//! // and perform the reencryption
//!
//! // Ursula 0
//! assert!(kfrags[0].verify(&verifying_pk, Some(&alice_pk), Some(&bob_pk)));
//! let metadata0 = b"metadata0";
//! let cfrag0 = reencrypt(&capsule, &kfrags[0], Some(metadata0));
//!
//! // Ursula 1
//! assert!(kfrags[1].verify(&verifying_pk, Some(&alice_pk), Some(&bob_pk)));
//! let metadata1 = b"metadata1";
//! let cfrag1 = reencrypt(&capsule, &kfrags[1], Some(metadata1));
//!
//! // ...
//!
//! // Finally, Bob opens the capsule by using at least `m` cfrags,
//! // and then decrypts the re-encrypted ciphertext.
//!
//! // Bob can optionally check that cfrags are valid
//! assert!(cfrag0.verify(&capsule, &verifying_pk, &alice_pk, &bob_pk, Some(metadata0)));
//! assert!(cfrag1.verify(&capsule, &verifying_pk, &alice_pk, &bob_pk, Some(metadata1)));
//!
//! let plaintext_bob = decrypt_reencrypted(
//!     &bob_sk, &alice_pk, &capsule, &[cfrag0, cfrag1], &ciphertext).unwrap();
//! assert_eq!(&plaintext_bob as &[u8], plaintext);
//! ```
//!
//! [umbral]: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

#![doc(html_root_url = "https://docs.rs/umbral-pre")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![no_std]

extern crate alloc;

pub mod bench; // Re-export some internals for benchmarks.
mod capsule;
mod capsule_frag;
mod curve;
mod dem;
mod hashing;
mod hashing_ds;
mod key_frag;
mod keys;
mod params;
mod pre;
mod traits;

pub use capsule::{Capsule, OpenReencryptedError};
pub use capsule_frag::CapsuleFrag;
pub use dem::{DecryptionError, EncryptionError};
pub use key_frag::KeyFrag;
pub use keys::{PublicKey, SecretKey, SecretKeyFactory, SecretKeyFactoryError, Signature, Signer};
pub use pre::{
    decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt, ReencryptionError,
};
pub use traits::{
    DeserializableFromArray, DeserializationError, RepresentableAsArray, SerializableToArray,
};
