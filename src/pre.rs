use crate::curve::{random_scalar, CurvePoint, CurveScalar, point_to_bytes};
use crate::random_oracles::{hash_to_scalar, kdf};
use crate::keys::{UmbralPrivateKey, UmbralPublicKey};
use crate::dem::{UmbralDEM, DEM_KEYSIZE, Ciphertext};
use crate::params::UmbralParameters;


#[derive(Clone, Copy, Debug)]
struct Capsule {
    params: UmbralParameters,
    point_e: CurvePoint,
    point_v: CurvePoint,
    bn_sig: CurveScalar
}

impl Capsule {
    fn new(params: &UmbralParameters, point_e: &CurvePoint, point_v: &CurvePoint, bn_sig: &CurveScalar) -> Self {
        Self {
            params: *params,
            point_e: *point_e,
            point_v: *point_v,
            bn_sig: *bn_sig
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let result: Vec<u8> =
            point_to_bytes(&(self.point_e)).iter().chain(
            point_to_bytes(&(self.point_v)).iter().chain(
            self.bn_sig.to_bytes().iter())).copied().collect();
        result
    }
}


/// Generates a symmetric key and its associated KEM ciphertext
fn _encapsulate(alice_pubkey: &UmbralPublicKey) -> (UmbralDEM, Capsule) {

    let params = alice_pubkey.params;
    let g = params.g;

    let priv_r = random_scalar();
    let pub_r = &g * &priv_r;

    let priv_u = random_scalar();
    let pub_u = &g * &priv_u;

    let h = hash_to_scalar(&[pub_r, pub_u]);
    let s = &priv_u + (&priv_r * &h);

    let shared_key = &(alice_pubkey.point_key) * &(&priv_r + &priv_u);

    // Key to be used for symmetric encryption
    let key = kdf(&shared_key, DEM_KEYSIZE, None, None);

    (UmbralDEM::new(&key), Capsule::new(&params, &pub_r, &pub_u, &s))
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

fn decrypt_original(ciphertext: &Ciphertext, capsule: &Capsule, decrypting_key: &UmbralPrivateKey) -> Option<Vec<u8>> {

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
fn decrypt_reencrypted(ciphertext: [u8],
                        capsule: &PreparedCapsule,
                        cfrags: [CapsuleFrag],
                        decrypting_key: &UmbralPrivateKey,
                        check_proof: bool) -> Result<[u8], > {

    // TODO: should be checked in a ciphertext object?
    //if len(ciphertext) < DEM_NONCE_SIZE:
    //    raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))
    // TODO: verify capsule on creation?
    //if !capsule.verify() {
    //    return Err(Capsule.NotValid)
    //}
    //elif not isinstance(decrypting_key, UmbralPrivateKey):
    //    raise TypeError("The decrypting key is not an UmbralPrivateKey")

    encapsulated_key = _open_capsule(capsule, cfrags, decrypting_key, check_proof);

    let dem = UmbralDEM(encapsulated_key);
    dem.decrypt(ciphertext, authenticated_data=bytes(capsule.capsule))
}
*/

#[cfg(test)]
mod tests {

    use crate::keys::UmbralPrivateKey;
    use crate::params::UmbralParameters;
    use crate::signing::Signer;
    use super::{encrypt, decrypt_original};

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

        let signer = Signer::new(&signing_privkey);

        // Key Generation (Bob)
        let receiving_privkey = UmbralPrivateKey::gen_key(&params);
        let receiving_pubkey = receiving_privkey.get_pubkey();

        // Encryption by an unnamed data source
        let plain_data = b"peace at dawn";
        let (ciphertext, capsule) = encrypt(&delegating_pubkey, plain_data);

        // Decryption by Alice
        let cleartext = decrypt_original(&ciphertext, &capsule, &delegating_privkey).unwrap();
        assert_eq!(cleartext, plain_data);

        /*
        // Split Re-Encryption Key Generation (aka Delegation)
        let kfrags = generate_kfrags(&delegating_privkey, &receiving_pubkey, M, N, &signer);


        // Capsule preparation (necessary before re-encryotion and activation)
        let prepared_capsule = capsule.with_correctness_keys(&delegating_pubkey,
                                                         &receiving_pubkey,
                                                         &signing_pubkey);

        // Bob requests re-encryption to some set of M ursulas
        let cfrags = Vec::new();
        for kfrag in kfrags[:M] {
            // Ursula checks that the received kfrag is valid
            assert!(kfrag.verify(&signing_pubkey, &delegating_pubkey, &receiving_pubkey, &params));

            // Re-encryption by an Ursula
            let cfrag = pre.reencrypt(kfrag, prepared_capsule);

            // Bob collects the result
            cfrags.push(cfrag);
        }

        // Decryption by Bob
        let reenc_cleartext = decrypt_reencrypted(&ciphertext, &prepared_capsule, &cfrags, &receiving_privkey);
        assert_eq!(reenc_cleartext, plain_data);
        */

    }
}
