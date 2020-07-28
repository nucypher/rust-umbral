use crate::capsule::{Capsule, PreparedCapsule};
use crate::cfrags::CapsuleFrag;
use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurveScalar};
use crate::dem::{Ciphertext, UmbralDEM, DEM_KEYSIZE};
use crate::keys::{UmbralPrivateKey, UmbralPublicKey};
use crate::kfrags::{serialize_key_type, KFrag, KeyType};
use crate::random_oracles::{hash_to_scalar, kdf};
use crate::utils::{lambda_coeff, poly_eval};

/// Generates a symmetric key and its associated KEM ciphertext
fn _encapsulate(alice_pubkey: &UmbralPublicKey) -> (UmbralDEM, Capsule) {
    let params = alice_pubkey.params;
    let g = params.g;

    let priv_r = random_scalar();
    let pub_r = &g * &priv_r;

    let priv_u = random_scalar();
    let pub_u = &g * &priv_u;

    let h = hash_to_scalar(&[pub_r, pub_u], None);

    let s = &priv_u + (&priv_r * &h);

    let shared_key = &(alice_pubkey.point_key) * &(&priv_r + &priv_u);

    // Key to be used for symmetric encryption
    let key = kdf(&shared_key, DEM_KEYSIZE, None, None);

    (
        UmbralDEM::new(&key),
        Capsule::new(&params, &pub_r, &pub_u, &s),
    )
}

/// Performs an encryption using the UmbralDEM object and encapsulates a key
/// for the sender using the public key provided.
///
/// Returns the ciphertext and the KEM Capsule.
fn encrypt(alice_pubkey: &UmbralPublicKey, plaintext: &[u8]) -> (Ciphertext, Capsule) {
    let (dem, capsule) = _encapsulate(alice_pubkey);
    let capsule_bytes = capsule.to_bytes();
    let ciphertext = dem.encrypt(plaintext, &capsule_bytes);
    (ciphertext, capsule)
}

/// Derive the same symmetric key
fn _decapsulate_original(private_key: &UmbralPrivateKey, capsule: &Capsule) -> Vec<u8> {
    // TODO: capsule should be verified on creation
    //if not capsule.verify():
    //    # Check correctness of original ciphertext
    //    raise capsule.NotValid("Capsule verification failed.")

    let shared_key = (&capsule.point_e + &capsule.point_v) * &private_key.bn_key;
    let key = kdf(&shared_key, DEM_KEYSIZE, None, None);
    key
}

fn decrypt_original(
    ciphertext: &Ciphertext,
    capsule: &Capsule,
    decrypting_key: &UmbralPrivateKey,
) -> Option<Vec<u8>> {
    // TODO: this should be checked in Ciphertext::from_bytes()
    //if not isinstance(ciphertext, bytes) or len(ciphertext) < DEM_NONCE_SIZE:
    //    raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))

    // TODO: capsule should perhaps be verified on creation?
    //elif not isinstance(capsule, Capsule) or not capsule.verify():
    //    raise Capsule.NotValid

    let encapsulated_key = _decapsulate_original(decrypting_key, capsule);
    let dem = UmbralDEM::new(&encapsulated_key);
    dem.decrypt(&ciphertext, &capsule.to_bytes())
}

/*
Creates a re-encryption key from Alice's delegating public key to Bob's
receiving public key, and splits it in KFrags, using Shamir's Secret Sharing.
Requires a threshold number of KFrags out of N.

Returns a list of N KFrags
*/
fn generate_kfrags(
    delegating_privkey: &UmbralPrivateKey,
    receiving_pubkey: &UmbralPublicKey,
    threshold: usize,
    N: usize,
    signer: &UmbralPrivateKey,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<KFrag> {
    // TODO: debug_assert!, or panic in release too?
    //if threshold <= 0 or threshold > N:
    //    raise ValueError('Arguments threshold and N must satisfy 0 < threshold <= N')
    //if delegating_privkey.params != receiving_pubkey.params:
    //    raise ValueError("Keys must have the same parameter set.")

    let params = delegating_privkey.params;
    let g = params.g;

    let delegating_pubkey = delegating_privkey.get_pubkey();

    let bob_pubkey_point = receiving_pubkey.point_key;

    // The precursor point is used as an ephemeral public key in a DH key exchange,
    // and the resulting shared secret 'dh_point' is used to derive other secret values
    let private_precursor = random_scalar();
    let precursor = &g * &private_precursor;

    let dh_point = &bob_pubkey_point * &private_precursor;

    // Secret value 'd' allows to make Umbral non-interactive
    let d = hash_to_scalar(
        &[precursor, bob_pubkey_point, dh_point],
        Some(&NON_INTERACTIVE),
    );

    // Coefficients of the generating polynomial
    let mut coefficients = Vec::<CurveScalar>::with_capacity(threshold);
    coefficients.push(&delegating_privkey.bn_key * &(d.invert().unwrap()));
    for i in 1..threshold {
        coefficients.push(random_scalar());
    }

    let mut kfrags = Vec::<KFrag>::with_capacity(N);
    for _i in 0..N {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = random_scalar();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let customization_string: Vec<u8> = X_COORDINATE
            .iter()
            .chain(scalar_to_bytes(&kfrag_id).iter())
            .copied()
            .collect();
        let share_index = hash_to_scalar(
            &[precursor, bob_pubkey_point, dh_point],
            Some(&customization_string),
        );

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = poly_eval(&coefficients, &share_index);

        let commitment = &params.u * &rk;

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_bob: Vec<u8> = scalar_to_bytes(&kfrag_id)
            .iter()
            .chain(delegating_pubkey.to_bytes().iter())
            .chain(receiving_pubkey.to_bytes().iter())
            .chain(point_to_bytes(&commitment).iter())
            .chain(point_to_bytes(&precursor).iter())
            .copied()
            .collect();
        let signature_for_bob = signer.sign(&validity_message_for_bob);

        // TODO: can be a function where KeyType is defined
        let mode = match (sign_delegating_key, sign_receiving_key) {
            (true, true) => KeyType::DelegatingAndReceiving,
            (true, false) => KeyType::DelegatingOnly,
            (false, true) => KeyType::ReceivingOnly,
            (false, false) => KeyType::NoKey,
        };

        // TODO: hide this in a special mutable object associated with Signer?
        let mut validity_message_for_proxy: Vec<u8> = scalar_to_bytes(&kfrag_id)
            .iter()
            .chain(point_to_bytes(&commitment).iter())
            .chain(point_to_bytes(&precursor).iter())
            .chain([serialize_key_type(&mode)].iter())
            .copied()
            .collect();

        if sign_delegating_key {
            validity_message_for_proxy.extend_from_slice(&delegating_pubkey.to_bytes());
        }
        if sign_receiving_key {
            validity_message_for_proxy.extend_from_slice(&receiving_pubkey.to_bytes());
        }

        let signature_for_proxy = signer.sign(&validity_message_for_proxy);

        let kfrag = KFrag::new(
            &params,
            &kfrag_id,
            &rk,
            &commitment,
            &precursor,
            &signature_for_proxy,
            &signature_for_bob,
            Some(mode),
        );

        kfrags.push(kfrag);
    }

    kfrags
}

fn reencrypt(
    kfrag: &KFrag,
    prepared_capsule: &PreparedCapsule,
    metadata: Option<&[u8]>,
    verify_kfrag: bool,
) -> Option<CapsuleFrag> {
    // TODO: verify on creation?
    //if not prepared_capsule.verify():
    //    raise Capsule.NotValid

    if verify_kfrag {
        if !prepared_capsule.verify_kfrag(&kfrag) {
            return None;
        }
    }

    Some(CapsuleFrag::from_kfrag(
        &prepared_capsule.capsule,
        &kfrag,
        metadata,
    ))
}

/// Derive the same symmetric encapsulated_key
fn _decapsulate_reencrypted(
    receiving_privkey: &UmbralPrivateKey,
    prepared_capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    key_length: usize,
) -> Vec<u8> {
    let capsule = prepared_capsule.capsule;
    let params = capsule.params;

    let pub_key = receiving_privkey.get_pubkey().point_key;
    let priv_key = receiving_privkey.bn_key;

    let precursor = cfrags[0].point_precursor;
    let dh_point = &precursor * &priv_key;

    // Combination of CFrags via Shamir's Secret Sharing reconstruction
    let mut xs = Vec::<CurveScalar>::new();
    for cfrag in cfrags {
        let customization_string: Vec<u8> = X_COORDINATE
            .iter()
            .chain(scalar_to_bytes(&cfrag.kfrag_id).iter())
            .copied()
            .collect();
        let x = hash_to_scalar(&[precursor, pub_key, dh_point], Some(&customization_string));
        xs.push(x);
    }

    let mut e_prime = CurvePoint::identity();
    let mut v_prime = CurvePoint::identity();
    for (cfrag, x) in (&cfrags).iter().zip((&xs).iter()) {
        assert!(precursor == cfrag.point_precursor);
        let lambda_i = lambda_coeff(&x, &xs);
        e_prime += &cfrag.point_e1 * &lambda_i;
        v_prime += &cfrag.point_v1 * &lambda_i;
    }

    // Secret value 'd' allows to make Umbral non-interactive
    let d = hash_to_scalar(&[precursor, pub_key, dh_point], Some(&NON_INTERACTIVE));

    let e = capsule.point_e;
    let v = capsule.point_v;
    let s = capsule.bn_sig;
    let h = hash_to_scalar(&[e, v], None);

    let orig_pub_key = prepared_capsule.delegating_key.point_key;

    assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
    //    raise GenericUmbralError()

    let shared_key = (&e_prime + &v_prime) * &d;

    kdf(&shared_key, key_length, None, None)
}

/*
Activates the Capsule from the attached CFrags,
opens the Capsule and returns what is inside.

This will often be a symmetric key.
*/
fn _open_capsule(
    prepared_capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    receiving_privkey: &UmbralPrivateKey,
    check_proof: bool,
) -> Vec<u8> {
    if check_proof {
        // TODO: return Result with Error set to offending cfrag indices or something
        for cfrag in cfrags {
            assert!(prepared_capsule.verify_cfrag(cfrag));
        }
    }

    _decapsulate_reencrypted(receiving_privkey, prepared_capsule, cfrags, DEM_KEYSIZE)
}

fn decrypt_reencrypted(
    ciphertext: &Ciphertext,
    capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    decrypting_key: &UmbralPrivateKey,
    check_proof: bool,
) -> Option<Vec<u8>> {
    // TODO: should be checked when creating a ciphertext object?
    //if len(ciphertext) < DEM_NONCE_SIZE:
    //    raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))
    // TODO: verify capsule on creation?
    //if !capsule.verify() {
    //    return Err(Capsule.NotValid)
    //}

    let encapsulated_key = _open_capsule(capsule, cfrags, decrypting_key, check_proof);
    let dem = UmbralDEM::new(&encapsulated_key);
    dem.decrypt(&ciphertext, &capsule.capsule.to_bytes())
}

#[cfg(test)]
mod tests {

    use super::{decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt};
    use crate::cfrags::CapsuleFrag;
    use crate::keys::UmbralPrivateKey;
    use crate::params::UmbralParameters;

    #[test]
    fn test_simple_api() {
        /*
        This test models the main interactions between NuCypher actors (i.e., Alice,
        Bob, Data Source, and Ursulas) and artifacts (i.e., public and private keys,
        ciphertexts, capsules, KFrags, CFrags, etc).

        The test covers all the main stages of data sharing with NuCypher:
        key generation, delegation, encryption, decryption by
        Alice, re-encryption by Ursula, and decryption by Bob.

        Manually injects umbralparameters for multi-curve testing.
        */

        let M = 2;
        let N = 3;

        // Generation of global parameters
        let params = UmbralParameters::new(); // TODO: parametrize by curve type

        // Key Generation (Alice)
        let delegating_privkey = UmbralPrivateKey::gen_key(&params);
        let delegating_pubkey = delegating_privkey.get_pubkey();

        let signing_privkey = UmbralPrivateKey::gen_key(&params);
        let signing_pubkey = signing_privkey.get_pubkey();

        // Key Generation (Bob)
        let receiving_privkey = UmbralPrivateKey::gen_key(&params);
        let receiving_pubkey = receiving_privkey.get_pubkey();

        // Encryption by an unnamed data source
        let plain_data = b"peace at dawn";
        let (ciphertext, capsule) = encrypt(&delegating_pubkey, plain_data);

        // Decryption by Alice
        let cleartext = decrypt_original(&ciphertext, &capsule, &delegating_privkey).unwrap();
        assert_eq!(cleartext, plain_data);

        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrags = generate_kfrags(
            &delegating_privkey,
            &receiving_pubkey,
            M,
            N,
            &signing_privkey,
            false,
            false,
        );

        // Capsule preparation (necessary before re-encryotion and activation)
        let prepared_capsule =
            capsule.with_correctness_keys(&delegating_pubkey, &receiving_pubkey, &signing_pubkey);

        // Bob requests re-encryption to some set of M ursulas
        let mut cfrags = Vec::<CapsuleFrag>::new();
        for frag_num in 0..M {
            let kfrag = &kfrags[frag_num];

            // Ursula checks that the received kfrag is valid
            assert!(kfrag.verify(
                &signing_pubkey,
                Some(&delegating_pubkey),
                Some(&receiving_pubkey)
            ));

            // Re-encryption by an Ursula
            let cfrag = reencrypt(&kfrag, &prepared_capsule, None, true).unwrap();

            // Bob collects the result
            cfrags.push(cfrag);
        }

        // Decryption by Bob
        let reenc_cleartext = decrypt_reencrypted(
            &ciphertext,
            &prepared_capsule,
            &cfrags,
            &receiving_privkey,
            true,
        );
        assert_eq!(reenc_cleartext.unwrap(), plain_data);
    }
}
