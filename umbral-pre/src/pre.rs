use crate::capsule::Capsule;
use crate::capsule_frag::CapsuleFrag;
use crate::curve::{UmbralPublicKey, UmbralSecretKey};
use crate::dem::UmbralDEM;
use crate::key_frag::KeyFrag;
use crate::params::UmbralParameters;
use crate::traits::SerializableToArray;

use alloc::boxed::Box;

/// Performs an encryption using the UmbralDEM object and encapsulates a key
/// for the sender using the public key provided.
///
/// Returns the ciphertext and the KEM Capsule.
pub fn encrypt(
    params: &UmbralParameters,
    delegating_pk: &UmbralPublicKey,
    plaintext: &[u8],
) -> (Capsule, Box<[u8]>) {
    let (capsule, key_seed) = Capsule::from_pubkey(params, delegating_pk);
    let dem = UmbralDEM::new(&key_seed);
    let capsule_bytes = capsule.to_array();
    let ciphertext = dem.encrypt(plaintext, &capsule_bytes);
    (capsule, ciphertext)
}

pub fn decrypt_original(
    decrypting_sk: &UmbralSecretKey,
    capsule: &Capsule,
    ciphertext: impl AsRef<[u8]>,
) -> Option<Box<[u8]>> {
    let key_seed = capsule.open_original(decrypting_sk);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt(ciphertext, &capsule.to_array())
}

pub fn reencrypt(kfrag: &KeyFrag, capsule: &Capsule, metadata: Option<&[u8]>) -> CapsuleFrag {
    CapsuleFrag::reencrypted(kfrag, capsule, metadata)
}

pub fn decrypt_reencrypted(
    decrypting_sk: &UmbralSecretKey,
    delegating_pk: &UmbralPublicKey,
    capsule: &Capsule,
    cfrags: &[CapsuleFrag],
    ciphertext: impl AsRef<[u8]>,
) -> Option<Box<[u8]>> {
    let key_seed = capsule.open_reencrypted(decrypting_sk, delegating_pk, cfrags);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt(&ciphertext, &capsule.to_array())
}

#[cfg(test)]
mod tests {

    use super::{decrypt_original, decrypt_reencrypted, encrypt, reencrypt};

    use crate::key_frag::generate_kfrags;

    use crate::capsule_frag::CapsuleFrag;

    use alloc::vec::Vec;

    use crate::{UmbralParameters, UmbralPublicKey, UmbralSecretKey};

    #[test]
    fn test_simple_api() {
        /*
        This test models the main interactions between NuCypher actors (i.e., Alice,
        Bob, Data Source, and Ursulas) and artifacts (i.e., public and private keys,
        ciphertexts, capsules, KeyFrags, CFrags, etc).

        The test covers all the main stages of data sharing with NuCypher:
        key generation, delegation, encryption, decryption by
        Alice, re-encryption by Ursula, and decryption by Bob.

        Manually injects umbralparameters for multi-curve testing.
        */

        let threshold: usize = 2;
        let num_frags: usize = threshold + 1;

        // Generation of global parameters
        let params = UmbralParameters::new();

        // Key Generation (Alice)
        let delegating_sk = UmbralSecretKey::random();
        let delegating_pk = UmbralPublicKey::from_secret_key(&delegating_sk);

        let signing_sk = UmbralSecretKey::random();
        let signing_pk = UmbralPublicKey::from_secret_key(&signing_sk);

        // Key Generation (Bob)
        let receiving_sk = UmbralSecretKey::random();
        let receiving_pk = UmbralPublicKey::from_secret_key(&receiving_sk);

        // Encryption by an unnamed data source
        let plaintext = b"peace at dawn";
        let (capsule, ciphertext) = encrypt(&params, &delegating_pk, plaintext);

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
            .map(|kfrag| reencrypt(&kfrag, &capsule, None))
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
