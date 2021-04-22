//! The high-level functional reencryption API.

use crate::capsule::{Capsule, OpenReencryptedError};
use crate::capsule_frag::CapsuleFrag;
use crate::dem::{DecryptionError, EncryptionError, DEM};
use crate::key_frag::{KeyFrag, KeyFragBase};
use crate::keys::{PublicKey, SecretKey, Signer};
use crate::traits::SerializableToArray;

use alloc::boxed::Box;
use alloc::vec::Vec;

/// Errors that can happen when decrypting a reencrypted ciphertext.
#[derive(Debug, PartialEq)]
pub enum ReencryptionError {
    /// An error when opening a capsule. See [`OpenReencryptedError`] for the options.
    OnOpen(OpenReencryptedError),
    /// An error when decrypting the ciphertext. See [`DecryptionError`] for the options.
    OnDecryption(DecryptionError),
}

/// Encrypts the given plaintext message using a DEM scheme,
/// and encapsulates the key for later reencryption.
/// Returns the KEM [`Capsule`] and the ciphertext.
pub fn encrypt(pk: &PublicKey, plaintext: &[u8]) -> Result<(Capsule, Box<[u8]>), EncryptionError> {
    let (capsule, key_seed) = Capsule::from_public_key(pk);
    let dem = DEM::new(&key_seed.to_array());
    let capsule_bytes = capsule.to_array();
    dem.encrypt(plaintext, &capsule_bytes)
        .map(|ciphertext| (capsule, ciphertext))
}

/// Attempts to decrypt the ciphertext using the original encryptor's
/// secret key.
pub fn decrypt_original(
    decrypting_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, DecryptionError> {
    let key_seed = capsule.open_original(decrypting_sk);
    let dem = DEM::new(&key_seed.to_array());
    dem.decrypt(ciphertext, &capsule.to_array())
}

/// Creates `num_kfrags` fragments of `delegating_sk`,
/// which will be possible to reencrypt to allow the creator of `receiving_pk`
/// decrypt the ciphertext encrypted with `delegating_sk`.
///
/// `threshold` sets the number of fragments necessary for decryption
/// (that is, fragments created with `threshold > num_frags` will be useless).
///
/// `signing_sk` is used to sign the resulting [`KeyFrag`] and
/// reencrypted [`CapsuleFrag`](`crate::CapsuleFrag`) objects, which can be later verified
/// by the associated public key.
///
/// If `sign_delegating_key` or `sign_receiving_key` are `true`,
/// the reencrypting party will be able to verify that a [`KeyFrag`]
/// corresponds to given delegating or receiving public keys
/// by supplying them to [`KeyFrag::verify()`].
///
/// Returns a boxed slice of `num_kfrags` KeyFrags
#[allow(clippy::too_many_arguments)]
pub fn generate_kfrags(
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signer: &Signer,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Box<[KeyFrag]> {
    let base = KeyFragBase::new(delegating_sk, receiving_pk, signer, threshold);

    let mut result = Vec::<KeyFrag>::new();
    for _ in 0..num_kfrags {
        result.push(KeyFrag::from_base(
            &base,
            sign_delegating_key,
            sign_receiving_key,
        ));
    }

    result.into_boxed_slice()
}

/// Reencrypts a [`Capsule`] object with a key fragment, creating a capsule fragment.
///
/// Having `threshold` (see [`generate_kfrags()`](`crate::generate_kfrags()`))
/// distinct fragments (along with the original capsule and the corresponding secret key)
/// allows one to decrypt the original plaintext.
///
/// One can call [`KeyFrag::verify()`] before reencryption to check its integrity.
pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<&[u8]>) -> CapsuleFrag {
    CapsuleFrag::reencrypted(capsule, kfrag, metadata)
}

/// Decrypts the ciphertext using previously reencrypted capsule fragments.
///
/// `decrypting_sk` is the secret key whose associated public key was used in
/// [`generate_kfrags()`](`crate::generate_kfrags()`).
///
/// `delegating_pk` is the public key of the encrypting party.
/// Used to check the validity of decryption.
///
/// One can call [`CapsuleFrag::verify()`] before reencryption to check its integrity.
pub fn decrypt_reencrypted(
    decrypting_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    cfrags: &[CapsuleFrag],
    ciphertext: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, ReencryptionError> {
    let key_seed = capsule
        .open_reencrypted(decrypting_sk, delegating_pk, cfrags)
        .map_err(ReencryptionError::OnOpen)?;
    let dem = DEM::new(&key_seed.to_array());
    dem.decrypt(&ciphertext, &capsule.to_array())
        .map_err(ReencryptionError::OnDecryption)
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use crate::{CapsuleFrag, PublicKey, SecretKey, Signer};

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
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let signer = Signer::new(&signing_sk);
        let verifying_pk = PublicKey::from_secret_key(&signing_sk);

        // Key Generation (Bob)
        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        // Encryption by an unnamed data source
        let plaintext = b"peace at dawn";
        let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        // Decryption by Alice
        let plaintext_alice = decrypt_original(&delegating_sk, &capsule, &ciphertext).unwrap();
        assert_eq!(&plaintext_alice as &[u8], plaintext);

        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrags = generate_kfrags(
            &delegating_sk,
            &receiving_pk,
            &signer,
            threshold,
            num_frags,
            true,
            true,
        );

        // Ursulas check that the received kfrags are valid
        assert!(kfrags.iter().all(|kfrag| kfrag.verify(
            &verifying_pk,
            Some(&delegating_pk),
            Some(&receiving_pk)
        )));

        // Bob requests re-encryption to some set of `threshold` ursulas
        let metadata = b"metadata";
        let cfrags: Vec<CapsuleFrag> = kfrags[0..threshold]
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag, Some(metadata)))
            .collect();

        // Bob checks that the received cfrags are valid
        assert!(cfrags.iter().all(|cfrag| cfrag.verify(
            &capsule,
            &verifying_pk,
            &delegating_pk,
            &receiving_pk,
            Some(metadata),
        )));

        // Decryption by Bob
        let plaintext_bob = decrypt_reencrypted(
            &receiving_sk,
            &delegating_pk,
            &capsule,
            &cfrags,
            &ciphertext,
        )
        .unwrap();
        assert_eq!(&plaintext_bob as &[u8], plaintext);
    }
}
