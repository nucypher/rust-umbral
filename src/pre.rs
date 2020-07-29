use crate::capsule::{Capsule, PreparedCapsule};
use crate::cfrags::CapsuleFrag;
use crate::constants::{const_non_interactive, const_x_coordinate};
use crate::curve::{point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurveScalar, CurvePointSize};
use crate::dem::{Ciphertext, UmbralDEM, DEM_KEYSIZE};
use crate::keys::{UmbralPrivateKey, UmbralPublicKey};
use crate::kfrags::{key_type_to_bytes, KFrag, KeyType};
use crate::random_oracles::{hash_to_scalar, kdf, KdfSize};
use crate::utils::{lambda_coeff, poly_eval};
use crate::params::UmbralParameters;

use aead::{Buffer};
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::{UInt, Unsigned};
use generic_array::sequence::Concat;

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

fn encrypt_in_place(buffer: &mut dyn Buffer, alice_pubkey: &UmbralPublicKey) -> Option<Capsule> {
    let (dem, capsule) = _encapsulate(alice_pubkey);
    let capsule_bytes = capsule.to_bytes();
    let result = dem.encrypt_in_place(buffer, &capsule_bytes);
    match result {
        Ok(_) => Some(capsule),
        Err(_) => None
    }
}

/// Derive the same symmetric key
fn _decapsulate_original(private_key: &UmbralPrivateKey, capsule: &Capsule) -> GenericArray<u8, KdfSize> {
    // TODO: capsule should be verified on creation
    //if not capsule.verify():
    //    # Check correctness of original ciphertext
    //    raise capsule.NotValid("Capsule verification failed.")

    let shared_key = (&capsule.point_e + &capsule.point_v) * &private_key.bn_key;
    kdf(&shared_key, DEM_KEYSIZE, None, None)
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

fn decrypt_original_in_place(
    buffer: &mut dyn Buffer,
    capsule: &Capsule,
    decrypting_key: &UmbralPrivateKey,
) -> Option<()> {
    // TODO: this should be checked in Ciphertext::from_bytes()
    //if not isinstance(ciphertext, bytes) or len(ciphertext) < DEM_NONCE_SIZE:
    //    raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))

    // TODO: capsule should perhaps be verified on creation?
    //elif not isinstance(capsule, Capsule) or not capsule.verify():
    //    raise Capsule.NotValid

    let encapsulated_key = _decapsulate_original(decrypting_key, capsule);
    let dem = UmbralDEM::new(&encapsulated_key);
    let res = dem.decrypt_in_place(buffer, &capsule.to_bytes());
    match res {
        Ok(_) => Some(()),
        Err(_) => None
    }
}

struct KFragFactory<M: ArrayLength<CurveScalar> + Unsigned> {
    signer: UmbralPrivateKey,
    precursor: CurvePoint,
    bob_pubkey_point: CurvePoint,
    dh_point: CurvePoint,
    params: UmbralParameters,
    delegating_pubkey: UmbralPublicKey,
    receiving_pubkey: UmbralPublicKey,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
    coefficients: GenericArray<CurveScalar, M>
}

impl<M: ArrayLength<CurveScalar> + Unsigned> KFragFactory<M> {

    pub fn new(delegating_privkey: &UmbralPrivateKey,
            receiving_pubkey: &UmbralPublicKey,
            threshold: usize,
            signer: &UmbralPrivateKey,
            sign_delegating_key: bool,
            sign_receiving_key: bool,) -> Self {

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
            Some(&const_non_interactive()),
        );

        // Coefficients of the generating polynomial
        let mut coefficients = GenericArray::<CurveScalar, M>::default();
        coefficients[0] = &delegating_privkey.bn_key * &(d.invert().unwrap());
        for i in 1..<M as Unsigned>::to_usize() {
            coefficients[i] = random_scalar();
        }

        Self {
            signer: *signer,
            precursor,
            bob_pubkey_point,
            dh_point,
            params,
            delegating_pubkey: delegating_pubkey,
            receiving_pubkey: *receiving_pubkey,
            sign_delegating_key,
            sign_receiving_key,
            coefficients
        }
    }

    pub fn make(&self) -> KFrag {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = random_scalar();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let customization_string = const_x_coordinate().concat(scalar_to_bytes(&kfrag_id));
        let share_index = hash_to_scalar(
            &[self.precursor, self.bob_pubkey_point, self.dh_point],
            Some(&customization_string),
        );

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = poly_eval(&self.coefficients, &share_index);

        let commitment = &self.params.u * &rk;

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_bob = scalar_to_bytes(&kfrag_id)
            .concat(self.delegating_pubkey.to_bytes())
            .concat(self.receiving_pubkey.to_bytes())
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&self.precursor));
        let signature_for_bob = self.signer.sign(&validity_message_for_bob);

        // TODO: can be a function where KeyType is defined
        let mode = match (self.sign_delegating_key, self.sign_receiving_key) {
            (true, true) => KeyType::DelegatingAndReceiving,
            (true, false) => KeyType::DelegatingOnly,
            (false, true) => KeyType::ReceivingOnly,
            (false, false) => KeyType::NoKey,
        };

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_proxy = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&self.precursor))
            .concat(key_type_to_bytes(&mode));

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.
        // TODO: question for @dnunez, @tux: is it safe to attach dummy keys to a message like that?

        let validity_message_for_proxy = validity_message_for_proxy
            .concat(if self.sign_delegating_key {
                self.delegating_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let validity_message_for_proxy = validity_message_for_proxy
            .concat(if self.sign_receiving_key {
                self.receiving_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let signature_for_proxy = self.signer.sign(&validity_message_for_proxy);

        KFrag::new(
            &self.params,
            &kfrag_id,
            &rk,
            &commitment,
            &self.precursor,
            &signature_for_proxy,
            &signature_for_bob,
            Some(mode),
        )
    }
}


/*
Creates a re-encryption key from Alice's delegating public key to Bob's
receiving public key, and splits it in KFrags, using Shamir's Secret Sharing.
Requires a threshold number of KFrags out of N.

Returns a list of N KFrags
*/
fn generate_kfrags(
    kfrags: &mut [KFrag],
    delegating_privkey: &UmbralPrivateKey,
    receiving_pubkey: &UmbralPublicKey,
    threshold: usize,
    N: usize,
    signer: &UmbralPrivateKey,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> bool {
    // TODO: debug_assert!, or panic in release too?
    //if threshold <= 0 or threshold > N:
    //    raise ValueError('Arguments threshold and N must satisfy 0 < threshold <= N')
    //if delegating_privkey.params != receiving_pubkey.params:
    //    raise ValueError("Keys must have the same parameter set.")

    assert!(kfrags.len() >= N);

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
        Some(&const_non_interactive()),
    );

    // Coefficients of the generating polynomial
    let mut coefficients = Vec::<CurveScalar>::with_capacity(threshold);
    coefficients.push(&delegating_privkey.bn_key * &(d.invert().unwrap()));
    for i in 1..threshold {
        coefficients.push(random_scalar());
    }

    for i in 0..N {
        // Was: `os.urandom(bn_size)`. But it seems we just want a scalar?
        let kfrag_id = random_scalar();

        // The index of the re-encryption key share (which in Shamir's Secret
        // Sharing corresponds to x in the tuple (x, f(x)), with f being the
        // generating polynomial), is used to prevent reconstruction of the
        // re-encryption key without Bob's intervention
        let customization_string = const_x_coordinate().concat(scalar_to_bytes(&kfrag_id));
        let share_index = hash_to_scalar(
            &[precursor, bob_pubkey_point, dh_point],
            Some(&customization_string),
        );

        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let rk = poly_eval(&coefficients, &share_index);

        let commitment = &params.u * &rk;

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_bob = scalar_to_bytes(&kfrag_id)
            .concat(delegating_pubkey.to_bytes())
            .concat(receiving_pubkey.to_bytes())
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&precursor));
        let signature_for_bob = signer.sign(&validity_message_for_bob);

        // TODO: can be a function where KeyType is defined
        let mode = match (sign_delegating_key, sign_receiving_key) {
            (true, true) => KeyType::DelegatingAndReceiving,
            (true, false) => KeyType::DelegatingOnly,
            (false, true) => KeyType::ReceivingOnly,
            (false, false) => KeyType::NoKey,
        };

        // TODO: hide this in a special mutable object associated with Signer?
        let validity_message_for_proxy = scalar_to_bytes(&kfrag_id)
            .concat(point_to_bytes(&commitment))
            .concat(point_to_bytes(&precursor))
            .concat(key_type_to_bytes(&mode));

        // `validity_message_for_proxy` needs to have a static type and
        // (since it's a GenericArray) a static size.
        // So we have to concat the same number of bytes regardless of any runtime state.
        // TODO: question for @dnunez, @tux: is it safe to attach dummy keys to a message like that?

        let validity_message_for_proxy = validity_message_for_proxy
            .concat(if sign_delegating_key {
                delegating_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

        let validity_message_for_proxy = validity_message_for_proxy
            .concat(if sign_receiving_key {
                receiving_pubkey.to_bytes()
            } else {
                GenericArray::<u8, CurvePointSize>::default()
            });

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

        kfrags[i] = kfrag;
    }

    true
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
) -> GenericArray<u8, KdfSize> {
    let capsule = prepared_capsule.capsule;
    let params = capsule.params;

    let pub_key = receiving_privkey.get_pubkey().point_key;
    let priv_key = receiving_privkey.bn_key;

    let precursor = cfrags[0].point_precursor;
    let dh_point = &precursor * &priv_key;

    // Combination of CFrags via Shamir's Secret Sharing reconstruction
    let mut xs = Vec::<CurveScalar>::new();
    for cfrag in cfrags {
        let customization_string = const_x_coordinate().concat(scalar_to_bytes(&cfrag.kfrag_id));
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
    let d = hash_to_scalar(&[precursor, pub_key, dh_point], Some(&const_non_interactive()));

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
) -> GenericArray<u8, KdfSize> {
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

fn decrypt_reencrypted_in_place(
    buffer: &mut dyn Buffer,
    capsule: &PreparedCapsule,
    cfrags: &[CapsuleFrag],
    decrypting_key: &UmbralPrivateKey,
    check_proof: bool,
) -> Option<()> {
    // TODO: should be checked when creating a ciphertext object?
    //if len(ciphertext) < DEM_NONCE_SIZE:
    //    raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))
    // TODO: verify capsule on creation?
    //if !capsule.verify() {
    //    return Err(Capsule.NotValid)
    //}

    let encapsulated_key = _open_capsule(capsule, cfrags, decrypting_key, check_proof);
    let dem = UmbralDEM::new(&encapsulated_key);
    let res = dem.decrypt_in_place(buffer, &capsule.capsule.to_bytes());
    match res {
        Ok(_) => Some(()),
        Err(_) => None
    }
}


#[cfg(test)]
mod tests {

    use super::{decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt};
    use crate::cfrags::CapsuleFrag;
    use crate::kfrags::KFrag;
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

        const M: usize = 2;
        const N: usize = 3;

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
        // FIXME: would be easier if KFrag implemented Copy, but for that Signature must implement Copy
        let mut kfrags = [KFrag::default(), KFrag::default(), KFrag::default()];
        let result = generate_kfrags(
            &mut kfrags,
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

    use super::{encrypt_in_place, decrypt_original_in_place, decrypt_reencrypted_in_place, KFragFactory};

    #[test]
    fn test_simple_api_heapless() {

        use heapless::Vec as HeaplessVec;
        use heapless::consts::U128;
        use generic_array::typenum::U2;

        const M: usize = 2;
        const N: usize = 3;

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
        let mut buffer: HeaplessVec<u8, U128> = HeaplessVec::new();
        buffer.extend_from_slice(plain_data);
        let capsule = encrypt_in_place(&mut buffer, &delegating_pubkey).unwrap();

        // Decryption by Alice
        let mut buffer2: HeaplessVec<u8, U128> = HeaplessVec::new();
        buffer2.extend_from_slice(buffer.as_ref());
        let result = decrypt_original_in_place(&mut buffer2, &capsule, &delegating_privkey).unwrap();
        assert_eq!(buffer2, plain_data);

        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrag_factory = KFragFactory::<U2>::new(
            &delegating_privkey,
            &receiving_pubkey,
            M,
            &signing_privkey,
            false,
            false,
        );

        let kfrags = [
            kfrag_factory.make(),
            kfrag_factory.make(),
            kfrag_factory.make()];

        // Capsule preparation (necessary before re-encryotion and activation)
        let prepared_capsule =
            capsule.with_correctness_keys(&delegating_pubkey, &receiving_pubkey, &signing_pubkey);

        // Bob requests re-encryption to some set of M ursulas
        for frag_num in 0..M {

            // Ursula checks that the received kfrag is valid
            assert!(kfrags[frag_num].verify(
                &signing_pubkey,
                Some(&delegating_pubkey),
                Some(&receiving_pubkey)
            ));
        }

        // Re-encryption by an Ursula
        let cfrag0 = reencrypt(&kfrags[0], &prepared_capsule, None, true).unwrap();
        let cfrag1 = reencrypt(&kfrags[1], &prepared_capsule, None, true).unwrap();

        // Decryption by Bob
        let result = decrypt_reencrypted_in_place(
            &mut buffer,
            &prepared_capsule,
            &[cfrag0, cfrag1],
            &receiving_privkey,
            true,
        ).unwrap();
        assert_eq!(buffer, plain_data);
    }
}
