use crate::capsule::{Capsule, PreparedCapsule};
use crate::capsule_frag::CapsuleFrag;
use crate::curve::{UmbralPublicKey, UmbralSecretKey};
use crate::dem::UmbralDEM;
use crate::params::UmbralParameters;
use crate::traits::SerializableToArray;

use alloc::vec::Vec;

/// Performs an encryption using the UmbralDEM object and encapsulates a key
/// for the sender using the public key provided.
///
/// Returns the ciphertext and the KEM Capsule.
pub fn encrypt(
    params: &UmbralParameters,
    pk: &UmbralPublicKey,
    plaintext: &[u8],
) -> (Vec<u8>, Capsule) {
    let (capsule, key_seed) = Capsule::from_pubkey(params, pk);
    let dem = UmbralDEM::new(&key_seed);
    let capsule_bytes = capsule.to_array();
    let ciphertext = dem.encrypt(plaintext, &capsule_bytes);
    (ciphertext, capsule)
}

pub fn decrypt_original(
    ciphertext: impl AsRef<[u8]>,
    capsule: &Capsule,
    decrypting_key: &UmbralSecretKey,
) -> Option<Vec<u8>> {
    let key_seed = capsule.open_original(decrypting_key);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt(ciphertext, &capsule.to_array())
}

pub fn decrypt_reencrypted(
    ciphertext: impl AsRef<[u8]>,
    capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    decrypting_key: &UmbralSecretKey,
    check_proof: bool,
) -> Option<Vec<u8>> {
    let key_seed = capsule.open_reencrypted(cfrags, decrypting_key, check_proof);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt(&ciphertext, &capsule.capsule.to_array())
}

#[cfg(test)]
mod tests {

    use super::{decrypt_original, decrypt_reencrypted, encrypt};

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
        let plain_data = b"peace at dawn";
        let (ciphertext, capsule) = encrypt(&params, &delegating_pk, plain_data);

        // Decryption by Alice
        let cleartext = decrypt_original(&ciphertext, &capsule, &delegating_sk).unwrap();
        assert_eq!(cleartext, plain_data);

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

        // Capsule preparation (necessary before re-encryotion and activation)
        let prepared_capsule =
            capsule.with_correctness_keys(&delegating_pk, &receiving_pk, &signing_pk);

        // Ursulas check that the received kfrags are valid
        assert!(kfrags.iter().all(|kfrag| kfrag.verify(
            &signing_pk,
            Some(&delegating_pk),
            Some(&receiving_pk)
        )));

        // Bob requests re-encryption to some set of `threshold` ursulas
        let cfrags: Vec<CapsuleFrag> = kfrags[0..threshold]
            .iter()
            .map(|kfrag| prepared_capsule.reencrypt(&kfrag, None, true).unwrap())
            .collect();

        // Decryption by Bob
        let reenc_cleartext =
            decrypt_reencrypted(&ciphertext, &prepared_capsule, &cfrags, &receiving_sk, true);
        assert_eq!(reenc_cleartext.unwrap(), plain_data);
    }
}
