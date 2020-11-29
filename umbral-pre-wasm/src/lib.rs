#![no_std]

extern crate alloc;

// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

use alloc::boxed::Box;
use alloc::{vec, vec::Vec};

#[wasm_bindgen]
pub struct SecretKey(umbral_pre::SecretKey);

#[wasm_bindgen]
impl SecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        console_error_panic_hook::set_once(); // TODO: find a better place to initialize it
        Self(umbral_pre::SecretKey::random())
    }
}

#[wasm_bindgen]
pub struct PublicKey(umbral_pre::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        Self(umbral_pre::PublicKey::from_secret_key(&secret_key.0))
    }
}

#[wasm_bindgen]
pub struct Parameters(umbral_pre::Parameters);

#[wasm_bindgen]
impl Parameters {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(umbral_pre::Parameters::new())
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Capsule(umbral_pre::Capsule);

#[wasm_bindgen]
impl Capsule {
    // FIXME: have to add cfrags one by one since `wasm_bindgen` currently does not support
    // Vec<CustomStruct> as a parameter.
    // Will probably be fixed along with https://github.com/rustwasm/wasm-bindgen/issues/111
    #[wasm_bindgen]
    pub fn with_cfrag(&self, cfrag: &CapsuleFrag) -> CapsuleWithFrags {
        CapsuleWithFrags {
            capsule: *self,
            cfrags: vec![cfrag.clone()],
        }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CapsuleFrag(umbral_pre::CapsuleFrag);

#[wasm_bindgen]
impl CapsuleFrag {
    #[wasm_bindgen]
    pub fn verify(
        &self,
        capsule: &Capsule,
        signing_pubkey: &PublicKey,
        delegating_pubkey: &PublicKey,
        receiving_pubkey: &PublicKey,
    ) -> bool {
        self.0.verify(
            &capsule.0,
            &signing_pubkey.0,
            &delegating_pubkey.0,
            &receiving_pubkey.0,
        )
    }
}

#[wasm_bindgen]
pub struct CapsuleWithFrags {
    capsule: Capsule,
    cfrags: Vec<CapsuleFrag>,
}

#[wasm_bindgen]
impl CapsuleWithFrags {
    #[wasm_bindgen]
    pub fn with_cfrag(&self, cfrag: &CapsuleFrag) -> CapsuleWithFrags {
        let mut new_cfrags = self.cfrags.clone();
        new_cfrags.push(cfrag.clone());
        Self {
            capsule: self.capsule,
            cfrags: new_cfrags,
        }
    }

    #[wasm_bindgen]
    pub fn decrypt_reencrypted(
        &self,
        decrypting_key: &SecretKey,
        delegating_pk: &PublicKey,
        ciphertext: &[u8],
    ) -> Option<Box<[u8]>> {
        let backend_cfrags: Vec<umbral_pre::CapsuleFrag> =
            self.cfrags.iter().cloned().map(|x| x.0).collect();
        umbral_pre::decrypt_reencrypted(
            &decrypting_key.0,
            &delegating_pk.0,
            &self.capsule.0,
            backend_cfrags.as_slice(),
            ciphertext,
        )
    }
}

#[wasm_bindgen]
pub struct EncryptionResult {
    ciphertext: Box<[u8]>,
    pub capsule: Capsule,
}

#[wasm_bindgen]
impl EncryptionResult {
    fn new(ciphertext: Box<[u8]>, capsule: Capsule) -> Self {
        Self {
            ciphertext,
            capsule,
        }
    }

    // FIXME: currently can't just make the field public because `Vec` doesn't implement `Copy`.
    // See https://github.com/rustwasm/wasm-bindgen/issues/439
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Box<[u8]> {
        self.ciphertext.clone()
    }
}

#[wasm_bindgen]
pub fn encrypt(
    params: &Parameters,
    alice_pubkey: &PublicKey,
    plaintext: &[u8],
) -> Option<EncryptionResult> {
    let backend_params = params.0;
    let backend_pubkey = alice_pubkey.0;
    let (capsule, ciphertext) =
        umbral_pre::encrypt(&backend_params, &backend_pubkey, plaintext).unwrap();
    Some(EncryptionResult::new(ciphertext, Capsule(capsule)))
}

#[wasm_bindgen]
pub fn decrypt_original(
    decrypting_key: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> Box<[u8]> {
    umbral_pre::decrypt_original(&decrypting_key.0, &capsule.0, ciphertext).unwrap()
}

#[wasm_bindgen]
pub struct KeyFrag(umbral_pre::KeyFrag);

#[wasm_bindgen]
impl KeyFrag {
    // FIXME: `Option<&PublicKey> are currently not supported.
    // See https://github.com/rustwasm/wasm-bindgen/issues/2370
    // So we have to use 4 functions instead of 1. Yikes.

    #[wasm_bindgen]
    pub fn verify(&self, signing_pubkey: &PublicKey) -> bool {
        self.0.verify(&signing_pubkey.0, None, None)
    }

    #[wasm_bindgen]
    pub fn verify_with_delegating_key(
        &self,
        signing_pubkey: &PublicKey,
        delegating_pubkey: &PublicKey,
    ) -> bool {
        let backend_delegating_pubkey = delegating_pubkey.0;

        self.0
            .verify(&signing_pubkey.0, Some(&backend_delegating_pubkey), None)
    }

    #[wasm_bindgen]
    pub fn verify_with_receiving_key(
        &self,
        signing_pubkey: &PublicKey,
        receiving_pubkey: &PublicKey,
    ) -> bool {
        let backend_receiving_pubkey = receiving_pubkey.0;

        self.0
            .verify(&signing_pubkey.0, None, Some(&backend_receiving_pubkey))
    }

    #[wasm_bindgen]
    pub fn verify_with_delegating_and_receiving_keys(
        &self,
        signing_pubkey: &PublicKey,
        delegating_pubkey: &PublicKey,
        receiving_pubkey: &PublicKey,
    ) -> bool {
        let backend_delegating_pubkey = delegating_pubkey.0;
        let backend_receiving_pubkey = receiving_pubkey.0;

        self.0.verify(
            &signing_pubkey.0,
            Some(&backend_delegating_pubkey),
            Some(&backend_receiving_pubkey),
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn generate_kfrags(
    params: &Parameters,
    delegating_sk: &SecretKey,
    receiving_pubkey: &PublicKey,
    signing_sk: &SecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<JsValue> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &params.0,
        &delegating_sk.0,
        &receiving_pubkey.0,
        &signing_sk.0,
        threshold,
        num_kfrags,
        sign_delegating_key,
        sign_receiving_key,
    );

    // FIXME: Apparently we cannot just return a vector of things,
    // so we have to convert them to JsValues manually.
    // See https://github.com/rustwasm/wasm-bindgen/issues/111
    backend_kfrags
        .iter()
        .cloned()
        .map(KeyFrag)
        .map(JsValue::from)
        .collect()
}

#[wasm_bindgen]
pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<Box<[u8]>>) -> CapsuleFrag {
    let metadata_slice = metadata.as_ref().map(|x| x.as_ref());
    let backend_cfrag = umbral_pre::reencrypt(&capsule.0, &kfrag.0, metadata_slice);
    CapsuleFrag(backend_cfrag)
}
