use generic_array::GenericArray;
use wasm_bindgen::prelude::wasm_bindgen;

use umbral;
use umbral::Serializable;

use std::vec::Vec;

use console_error_panic_hook;

#[wasm_bindgen]
pub struct UmbralSecretKey(GenericArray<u8, <umbral::UmbralSecretKey as Serializable>::Size>);

#[wasm_bindgen]
impl UmbralSecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        console_error_panic_hook::set_once(); // TODO: find a better place to initialize it
        Self(umbral::UmbralSecretKey::random().to_bytes())
    }

    pub(crate) fn to_backend(&self) -> umbral::UmbralSecretKey {
        umbral::UmbralSecretKey::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct UmbralPublicKey(GenericArray<u8, <umbral::UmbralPublicKey as Serializable>::Size>);

#[wasm_bindgen]
impl UmbralPublicKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn from_secret_key(secret_key: &UmbralSecretKey) -> Self {
        let sk = secret_key.to_backend();
        Self(umbral::UmbralPublicKey::from_secret_key(&sk).to_bytes())
    }

    pub(crate) fn to_backend(&self) -> umbral::UmbralPublicKey {
        umbral::UmbralPublicKey::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct UmbralParameters(GenericArray<u8, <umbral::UmbralParameters as Serializable>::Size>);

#[wasm_bindgen]
impl UmbralParameters {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(umbral::UmbralParameters::new().to_bytes())
    }

    pub(crate) fn to_backend(&self) -> umbral::UmbralParameters {
        umbral::UmbralParameters::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Capsule(GenericArray<u8, <umbral::Capsule as Serializable>::Size>);

impl Capsule {
    fn from_backend(capsule: &umbral::Capsule) -> Self {
        Self(capsule.to_bytes())
    }

    fn to_backend(&self) -> umbral::Capsule {
        umbral::Capsule::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct EncryptionResult {
    ciphertext: Vec<u8>,
    pub capsule: Capsule,
}

#[wasm_bindgen]
impl EncryptionResult {
    fn new(ciphertext: Vec<u8>, capsule: Capsule) -> Self {
        Self {
            ciphertext: ciphertext,
            capsule: capsule,
        }
    }

    // Can't just make the field public because `Vec` doesn't implement `Copy`.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

#[wasm_bindgen]
pub fn encrypt(
    params: &UmbralParameters,
    alice_pubkey: &UmbralPublicKey,
    plaintext: &[u8],
) -> EncryptionResult {
    let backend_params = params.to_backend();
    let backend_pubkey = alice_pubkey.to_backend();
    let (ciphertext, capsule) = umbral::encrypt(&backend_params, &backend_pubkey, plaintext);
    EncryptionResult::new(ciphertext, Capsule::from_backend(&capsule))
}

#[wasm_bindgen]
pub fn decrypt_original(
    ciphertext: &[u8],
    capsule: &Capsule,
    decrypting_key: &UmbralSecretKey,
) -> Vec<u8> {
    let backend_capsule = capsule.to_backend();
    let backend_key = decrypting_key.to_backend();
    umbral::decrypt_original(ciphertext, &backend_capsule, &backend_key).unwrap()
}
