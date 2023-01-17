//! The high-level functional reencryption API.

use core::fmt;

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "default-rng")]
use rand_core::OsRng;

use crate::capsule::{Capsule, OpenReencryptedError};
use crate::capsule_frag::VerifiedCapsuleFrag;
use crate::dem::{DecryptionError, EncryptionError, DEM};
use crate::key_frag::{KeyFragBase, VerifiedKeyFrag};
use crate::keys::{PublicKey, SecretKey, Signer};

use alloc::boxed::Box;
use alloc::vec::Vec;

/// Errors that can happen when decrypting a reencrypted ciphertext.
#[derive(Debug, PartialEq, Eq)]
pub enum ReencryptionError {
    /// An error when opening a capsule. See [`OpenReencryptedError`] for the options.
    OnOpen(OpenReencryptedError),
    /// An error when decrypting the ciphertext. See [`DecryptionError`] for the options.
    OnDecryption(DecryptionError),
}

impl fmt::Display for ReencryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OnOpen(err) => write!(f, "Re-encryption error on open: {}", err),
            Self::OnDecryption(err) => write!(f, "Re-encryption error on decryption: {}", err),
        }
    }
}

/// Encrypts the given plaintext message using a DEM scheme,
/// and encapsulates the key for later reencryption.
/// Returns the KEM [`Capsule`] and the ciphertext.
pub fn encrypt_with_rng(
    rng: &mut (impl CryptoRng + RngCore),
    delegating_pk: &PublicKey,
    plaintext: &[u8],
) -> Result<(Capsule, Box<[u8]>), EncryptionError> {
    let (capsule, key_seed) = Capsule::from_public_key(rng, delegating_pk);
    let dem = DEM::new(key_seed.as_secret());
    dem.encrypt(rng, plaintext, &capsule.to_bytes_simple())
        .map(|ciphertext| (capsule, ciphertext))
}

/// A synonym for [`encrypt`] with the default RNG.
#[cfg(feature = "default-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
pub fn encrypt(
    delegating_pk: &PublicKey,
    plaintext: &[u8],
) -> Result<(Capsule, Box<[u8]>), EncryptionError> {
    encrypt_with_rng(&mut OsRng, delegating_pk, plaintext)
}

/// Attempts to decrypt the ciphertext using the receiver's secret key.
pub fn decrypt_original(
    delegating_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, DecryptionError> {
    let key_seed = capsule.open_original(delegating_sk);
    let dem = DEM::new(key_seed.as_secret());
    dem.decrypt(ciphertext, &capsule.to_bytes_simple())
}

/// Creates `shares` fragments of `delegating_sk`,
/// which will be possible to reencrypt to allow the creator of `receiving_pk`
/// decrypt the ciphertext encrypted with `delegating_sk`.
///
/// `threshold` sets the number of fragments necessary for decryption
/// (that is, fragments created with `threshold > num_frags` will be useless).
///
/// `signer` is used to sign the resulting [`KeyFrag`](`crate::KeyFrag`) objects,
/// which can be later verified by the associated public key.
///
/// If `sign_delegating_key` or `sign_receiving_key` are `true`,
/// the reencrypting party will be able to verify that a [`KeyFrag`](`crate::KeyFrag`)
/// corresponds to given delegating or receiving public keys
/// by supplying them to [`KeyFrag::verify()`](`crate::KeyFrag::verify`).
///
/// Returns a boxed slice of `shares` KeyFrags
#[allow(clippy::too_many_arguments)]
pub fn generate_kfrags_with_rng(
    rng: &mut (impl CryptoRng + RngCore),
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signer: &Signer,
    threshold: usize,
    shares: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Box<[VerifiedKeyFrag]> {
    let base = KeyFragBase::new(rng, delegating_sk, receiving_pk, signer, threshold);

    let mut result = Vec::<VerifiedKeyFrag>::new();
    for _ in 0..shares {
        result.push(VerifiedKeyFrag::from_base(
            rng,
            &base,
            sign_delegating_key,
            sign_receiving_key,
        ));
    }

    result.into_boxed_slice()
}

/// A synonym for [`generate_kfrags_with_rng`] with the default RNG.
#[cfg(feature = "default-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
#[allow(clippy::too_many_arguments)]
pub fn generate_kfrags(
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signer: &Signer,
    threshold: usize,
    shares: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Box<[VerifiedKeyFrag]> {
    generate_kfrags_with_rng(
        &mut OsRng,
        delegating_sk,
        receiving_pk,
        signer,
        threshold,
        shares,
        sign_delegating_key,
        sign_receiving_key,
    )
}

/// Reencrypts a [`Capsule`] object with a key fragment, creating a capsule fragment.
///
/// Having `threshold` (see [`generate_kfrags()`](`crate::generate_kfrags()`))
/// distinct fragments (along with the original capsule and the corresponding secret key)
/// allows one to decrypt the original plaintext.
///
/// One can call [`KeyFrag::verify()`](`crate::KeyFrag::verify`)
/// before reencryption to check its integrity.
pub fn reencrypt_with_rng(
    rng: &mut (impl CryptoRng + RngCore),
    capsule: &Capsule,
    verified_kfrag: VerifiedKeyFrag,
) -> VerifiedCapsuleFrag {
    VerifiedCapsuleFrag::reencrypted(rng, capsule, verified_kfrag.unverify())
}

/// A synonym for [`reencrypt_with_rng`] with the default RNG.
#[cfg(feature = "default-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
pub fn reencrypt(capsule: &Capsule, verified_kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag {
    reencrypt_with_rng(&mut OsRng, capsule, verified_kfrag)
}

/// Decrypts the ciphertext using previously reencrypted capsule fragments.
///
/// `decrypting_sk` is the secret key whose associated public key was used in
/// [`generate_kfrags()`](`crate::generate_kfrags()`).
///
/// `delegating_pk` is the public key of the encrypting party.
/// Used to check the validity of decryption.
///
/// One can call [`CapsuleFrag::verify()`](`crate::CapsuleFrag::verify`)
/// before reencryption to check its integrity.
pub fn decrypt_reencrypted(
    receiving_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    verified_cfrags: impl IntoIterator<Item = VerifiedCapsuleFrag>,
    ciphertext: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, ReencryptionError> {
    let cfrags: Vec<_> = verified_cfrags
        .into_iter()
        .map(|vcfrag| vcfrag.unverify())
        .collect();
    let key_seed = capsule
        .open_reencrypted(receiving_sk, delegating_pk, &cfrags)
        .map_err(ReencryptionError::OnOpen)?;
    let dem = DEM::new(key_seed.as_secret());
    dem.decrypt(&ciphertext, &capsule.to_bytes_simple())
        .map_err(ReencryptionError::OnDecryption)
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use crate::{SecretKey, Signer, VerifiedCapsuleFrag};

    use super::{decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt};

    #[test]
    fn test_simple_api() {
        /*
        This test models the main interactions between NuCypher actors (i.e., Alice,
        Bob, Data Source, and Ursulas) and artifacts (i.e., public and private keys,
        ciphertexts, capsules, KeyFrags, CapsuleFrags, etc).

        The test covers all the main stages of data sharing with NuCypher:
        key generation, delegation, encryption, decryption by
        Alice, re-encryption by Ursula, and decryption by Bob.
        */

        let threshold: usize = 2;
        let num_frags: usize = threshold + 1;

        // Key Generation (Alice)
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let signer = Signer::new(SecretKey::random());
        let verifying_pk = signer.verifying_key();

        // Key Generation (Bob)
        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();

        // Encryption by an unnamed data source
        let plaintext = b"peace at dawn";
        let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        // Decryption by Alice
        let plaintext_alice = decrypt_original(&delegating_sk, &capsule, &ciphertext).unwrap();
        assert_eq!(&plaintext_alice as &[u8], plaintext);

        // Split Re-Encryption Key Generation (aka Delegation)
        let verified_kfrags = generate_kfrags(
            &delegating_sk,
            &receiving_pk,
            &signer,
            threshold,
            num_frags,
            true,
            true,
        );

        // Bob requests re-encryption to some set of `threshold` ursulas

        // Simulate network transfer
        let kfrags = verified_kfrags
            .iter()
            .cloned()
            .map(|vkfrag| vkfrag.unverify());

        // If Ursula received kfrags from the network, she must check that they are valid
        let verified_kfrags: Vec<_> = kfrags
            .into_iter()
            .map(|kfrag| {
                kfrag
                    .verify(&verifying_pk, Some(&delegating_pk), Some(&receiving_pk))
                    .unwrap()
            })
            .collect();

        let verified_cfrags: Vec<VerifiedCapsuleFrag> = verified_kfrags[0..threshold]
            .iter()
            .map(|vkfrag| reencrypt(&capsule, vkfrag.clone()))
            .collect();

        // Simulate network transfer
        let cfrags = verified_cfrags
            .iter()
            .cloned()
            .map(|vcfrag| vcfrag.unverify());

        // If Bob received cfrags from the network, he must check that they are valid
        let verified_cfrags: Vec<_> = cfrags
            .into_iter()
            .map(|cfrag| {
                cfrag
                    .verify(&capsule, &verifying_pk, &delegating_pk, &receiving_pk)
                    .unwrap()
            })
            .collect();

        // Decryption by Bob
        let plaintext_bob = decrypt_reencrypted(
            &receiving_sk,
            &delegating_pk,
            &capsule,
            verified_cfrags,
            &ciphertext,
        )
        .unwrap();
        assert_eq!(&plaintext_bob as &[u8], plaintext);
    }
}
