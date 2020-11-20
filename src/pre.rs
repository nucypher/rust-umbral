use crate::capsule::{Capsule, PreparedCapsule};
use crate::capsule_frag::CapsuleFrag;
use crate::curve::CurveScalar;

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::curve::{UmbralPublicKey, UmbralSecretKey};
use crate::dem::UmbralDEM;
use crate::params::UmbralParameters;

use aead::Buffer;
use generic_array::typenum::Unsigned;
use generic_array::ArrayLength;

/// Performs an encryption using the UmbralDEM object and encapsulates a key
/// for the sender using the public key provided.
///
/// Returns the ciphertext and the KEM Capsule.
#[cfg(feature = "std")]
pub fn encrypt(
    params: &UmbralParameters,
    alice_pubkey: &UmbralPublicKey,
    plaintext: &[u8],
) -> (Vec<u8>, Capsule) {
    let (capsule, key_seed) = Capsule::from_pubkey(params, alice_pubkey);
    let dem = UmbralDEM::new(&key_seed);
    let capsule_bytes = capsule.to_bytes();
    let ciphertext = dem.encrypt(plaintext, &capsule_bytes);
    (ciphertext, capsule)
}

pub fn encrypt_in_place(
    params: &UmbralParameters,
    buffer: &mut dyn Buffer,
    alice_pubkey: &UmbralPublicKey,
) -> Option<Capsule> {
    let (capsule, key_seed) = Capsule::from_pubkey(params, alice_pubkey);
    let dem = UmbralDEM::new(&key_seed);
    let capsule_bytes = capsule.to_bytes();
    let result = dem.encrypt_in_place(buffer, &capsule_bytes);
    match result {
        Some(_) => Some(capsule),
        None => None,
    }
}

#[cfg(feature = "std")]
pub fn decrypt_original(
    ciphertext: &Vec<u8>,
    capsule: &Capsule,
    decrypting_key: &UmbralSecretKey,
) -> Option<Vec<u8>> {
    let key_seed = capsule.open_original(decrypting_key);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt(&ciphertext, &capsule.to_bytes())
}

pub fn decrypt_original_in_place(
    buffer: &mut dyn Buffer,
    capsule: &Capsule,
    decrypting_key: &UmbralSecretKey,
) -> Option<()> {
    let key_seed = capsule.open_original(decrypting_key);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt_in_place(buffer, &capsule.to_bytes())
}

#[cfg(feature = "std")]
pub fn decrypt_reencrypted(
    ciphertext: &Vec<u8>,
    capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    decrypting_key: &UmbralSecretKey,
    check_proof: bool,
) -> Option<Vec<u8>> {
    let key_seed = capsule.open_reencrypted(cfrags, decrypting_key, check_proof);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt(&ciphertext, &capsule.capsule.to_bytes())
}

pub fn decrypt_reencrypted_in_place<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    buffer: &mut dyn Buffer,
    capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    decrypting_key: &UmbralSecretKey,
    check_proof: bool,
) -> Option<()> {
    let key_seed =
        capsule.open_reencrypted_heapless::<Threshold>(cfrags, decrypting_key, check_proof);
    let dem = UmbralDEM::new(&key_seed);
    dem.decrypt_in_place(buffer, &capsule.capsule.to_bytes())
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "std")]
    use super::{decrypt_original, decrypt_reencrypted, encrypt};

    #[cfg(feature = "std")]
    use crate::key_frag::generate_kfrags;

    #[cfg(feature = "std")]
    use crate::capsule_frag::CapsuleFrag;

    #[cfg(feature = "std")]
    use std::vec::Vec;

    use crate::{UmbralParameters, UmbralPublicKey, UmbralSecretKey};

    #[cfg(feature = "std")]
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
        let delegating_privkey = UmbralSecretKey::random();
        let delegating_pubkey = UmbralPublicKey::from_secret_key(&delegating_privkey);

        let signing_privkey = UmbralSecretKey::random();
        let signing_pubkey = UmbralPublicKey::from_secret_key(&signing_privkey);

        // Key Generation (Bob)
        let receiving_privkey = UmbralSecretKey::random();
        let receiving_pubkey = UmbralPublicKey::from_secret_key(&receiving_privkey);

        // Encryption by an unnamed data source
        let plain_data = b"peace at dawn";
        let (ciphertext, capsule) = encrypt(&params, &delegating_pubkey, plain_data);

        // Decryption by Alice
        let cleartext = decrypt_original(&ciphertext, &capsule, &delegating_privkey).unwrap();
        assert_eq!(cleartext, plain_data);

        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrags = generate_kfrags(
            &params,
            &delegating_privkey,
            &receiving_pubkey,
            &signing_privkey,
            threshold,
            num_frags,
            true,
            true,
        );

        // Capsule preparation (necessary before re-encryotion and activation)
        let prepared_capsule =
            capsule.with_correctness_keys(&delegating_pubkey, &receiving_pubkey, &signing_pubkey);

        // Ursulas check that the received kfrags are valid
        assert!(kfrags.iter().all(|kfrag| kfrag.verify(
            &signing_pubkey,
            Some(&delegating_pubkey),
            Some(&receiving_pubkey)
        )));

        // Bob requests re-encryption to some set of `threshold` ursulas
        let cfrags: Vec<CapsuleFrag> = kfrags[0..threshold]
            .iter()
            .map(|kfrag| prepared_capsule.reencrypt(&kfrag, None, true).unwrap())
            .collect();

        // Decryption by Bob
        let reenc_cleartext = decrypt_reencrypted(
            &ciphertext,
            &prepared_capsule,
            &cfrags,
            &receiving_privkey,
            true,
        );
        assert_eq!(reenc_cleartext.unwrap(), plain_data);
    }

    use super::{decrypt_original_in_place, decrypt_reencrypted_in_place, encrypt_in_place};
    use crate::key_frag::KeyFragFactoryHeapless;

    #[test]
    fn test_simple_api_heapless() {
        use generic_array::typenum::{Unsigned, U2};
        use heapless::consts::U128;
        use heapless::Vec as HeaplessVec;

        type Threshold = U2;
        let threshold: usize = <Threshold as Unsigned>::to_usize();

        // Generation of global parameters
        let params = UmbralParameters::new();

        // Key Generation (Alice)
        let delegating_privkey = UmbralSecretKey::random();
        let delegating_pubkey = UmbralPublicKey::from_secret_key(&delegating_privkey);

        let signing_privkey = UmbralSecretKey::random();
        let signing_pubkey = UmbralPublicKey::from_secret_key(&signing_privkey);

        // Key Generation (Bob)
        let receiving_privkey = UmbralSecretKey::random();
        let receiving_pubkey = UmbralPublicKey::from_secret_key(&receiving_privkey);

        // Encryption by an unnamed data source
        let plain_data = b"peace at dawn";
        let mut buffer: HeaplessVec<u8, U128> = HeaplessVec::new();
        buffer.extend_from_slice(plain_data).unwrap();
        let capsule = encrypt_in_place(&params, &mut buffer, &delegating_pubkey).unwrap();

        // Decryption by Alice
        let mut buffer2: HeaplessVec<u8, U128> = HeaplessVec::new();
        buffer2.extend_from_slice(buffer.as_ref()).unwrap();
        decrypt_original_in_place(&mut buffer2, &capsule, &delegating_privkey).unwrap();
        assert_eq!(buffer2, plain_data);

        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrag_factory = KeyFragFactoryHeapless::<Threshold>::new(
            &params,
            &delegating_privkey,
            &receiving_pubkey,
            &signing_privkey,
        );

        let kfrags = [
            kfrag_factory.make(true, true),
            kfrag_factory.make(true, true),
            kfrag_factory.make(true, true),
        ];

        // Capsule preparation (necessary before re-encryotion and activation)
        let prepared_capsule =
            capsule.with_correctness_keys(&delegating_pubkey, &receiving_pubkey, &signing_pubkey);

        // Bob requests re-encryption to some set of `threshold` ursulas
        for frag_num in 0..threshold {
            // Ursula checks that the received kfrag is valid
            assert!(kfrags[frag_num].verify(
                &signing_pubkey,
                Some(&delegating_pubkey),
                Some(&receiving_pubkey)
            ));
        }

        // Re-encryption by an Ursula
        let cfrag0 = prepared_capsule.reencrypt(&kfrags[0], None, true).unwrap();
        let cfrag1 = prepared_capsule.reencrypt(&kfrags[1], None, true).unwrap();

        // Decryption by Bob
        decrypt_reencrypted_in_place::<Threshold>(
            &mut buffer,
            &prepared_capsule,
            &[cfrag0, cfrag1],
            &receiving_privkey,
            true,
        )
        .unwrap();
        assert_eq!(buffer, plain_data);
    }
}
