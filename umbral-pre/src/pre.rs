//! The high-level functional reencryption API.

use crate::capsule::Capsule;
use crate::capsule_frag::CapsuleFrag;
use crate::curve::{PublicKey, SecretKey};
use crate::dem::UmbralDEM;
use crate::key_frag::KeyFrag;
use crate::params::Parameters;
use crate::traits::SerializableToArray;

use alloc::boxed::Box;

/// Encrypts the given plaintext message using a DEM scheme,
/// and encapsulates the key for later reencryption.
/// Returns the KEM [`Capsule`] and the ciphertext.
pub fn encrypt(
    params: &Parameters,
    pk: &PublicKey,
    plaintext: &[u8],
) -> Option<(Capsule, Box<[u8]>)> {
    let (capsule, key_seed) = Capsule::from_pubkey(params, pk);
    let dem = UmbralDEM::new(&key_seed.to_array());
    let capsule_bytes = capsule.to_array();
    let ciphertext = dem.encrypt(plaintext, &capsule_bytes)?;
    Some((capsule, ciphertext))
}

/// Attempts to decrypt the ciphertext using the original encryptor's
/// secret key.
pub fn decrypt_original(
    decrypting_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: impl AsRef<[u8]>,
) -> Option<Box<[u8]>> {
    let key_seed = capsule.open_original(decrypting_sk);
    let dem = UmbralDEM::new(&key_seed.to_array());
    dem.decrypt(ciphertext, &capsule.to_array())
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
) -> Option<Box<[u8]>> {
    let key_seed = capsule.open_reencrypted(decrypting_sk, delegating_pk, cfrags)?;
    let dem = UmbralDEM::new(&key_seed.to_array());
    dem.decrypt(&ciphertext, &capsule.to_array())
}

#[cfg(test)]
mod tests {

    use super::{decrypt_original, decrypt_reencrypted, encrypt, reencrypt};

    use crate::key_frag::generate_kfrags;

    use crate::capsule_frag::CapsuleFrag;

    use alloc::vec::Vec;

    use crate::{Parameters, PublicKey, SecretKey};

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

        // Generation of global parameters
        let params = Parameters::new();

        // Key Generation (Alice)
        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();
        let signing_pk = PublicKey::from_secret_key(&signing_sk);

        // Key Generation (Bob)
        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        // Encryption by an unnamed data source
        let plaintext = b"peace at dawn";
        let (capsule, ciphertext) = encrypt(&params, &delegating_pk, plaintext).unwrap();

        // Decryption by Alice
        let plaintext_alice = decrypt_original(&delegating_sk, &capsule, &ciphertext).unwrap();
        assert_eq!(&plaintext_alice as &[u8], plaintext);

        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrags = generate_kfrags(
            &params,
            &delegating_sk,
            &receiving_pk,
            &signing_sk,
            threshold,
            num_frags,
            true,
            true,
        );

        // Ursulas check that the received kfrags are valid
        assert!(kfrags.iter().all(|kfrag| kfrag.verify(
            &signing_pk,
            Some(&delegating_pk),
            Some(&receiving_pk)
        )));

        // Bob requests re-encryption to some set of `threshold` ursulas
        let cfrags: Vec<CapsuleFrag> = kfrags[0..threshold]
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag, None))
            .collect();

        // Bob checks that the received cfrags are valid
        assert!(cfrags.iter().all(|cfrag| cfrag.verify(
            &capsule,
            &delegating_pk,
            &receiving_pk,
            &signing_pk,
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
