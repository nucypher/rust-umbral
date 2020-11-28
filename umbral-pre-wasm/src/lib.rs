#![no_std]

extern crate alloc;

// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use generic_array::GenericArray;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

use umbral_pre::SerializableToArray;

use alloc::boxed::Box;
use alloc::{vec, vec::Vec};

#[wasm_bindgen]
pub struct UmbralSecretKey(
    GenericArray<u8, <umbral_pre::UmbralSecretKey as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl UmbralSecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        console_error_panic_hook::set_once(); // TODO: find a better place to initialize it
        Self(umbral_pre::UmbralSecretKey::random().to_array())
    }

    pub(crate) fn to_backend(&self) -> umbral_pre::UmbralSecretKey {
        umbral_pre::UmbralSecretKey::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct UmbralPublicKey(
    GenericArray<u8, <umbral_pre::UmbralPublicKey as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl UmbralPublicKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn from_secret_key(secret_key: &UmbralSecretKey) -> Self {
        let sk = secret_key.to_backend();
        Self(umbral_pre::UmbralPublicKey::from_secret_key(&sk).to_array())
    }

    pub(crate) fn to_backend(&self) -> umbral_pre::UmbralPublicKey {
        umbral_pre::UmbralPublicKey::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct UmbralParameters(
    GenericArray<u8, <umbral_pre::UmbralParameters as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl UmbralParameters {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(umbral_pre::UmbralParameters::new().to_array())
    }

    pub(crate) fn to_backend(&self) -> umbral_pre::UmbralParameters {
        umbral_pre::UmbralParameters::from_bytes(&self.0).unwrap()
    }
}

impl Default for UmbralParameters {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Capsule(GenericArray<u8, <umbral_pre::Capsule as SerializableToArray>::Size>);

#[wasm_bindgen]
impl Capsule {
    fn from_backend(capsule: &umbral_pre::Capsule) -> Self {
        Self(capsule.to_array())
    }

    fn to_backend(&self) -> umbral_pre::Capsule {
        umbral_pre::Capsule::from_bytes(&self.0).unwrap()
    }

    // FIXME: have to add cfrags one by one since `wasm_bindgen` currently does not support
    // Vec<CustomStruct> as a parameter.
    // Will probably be fixed along with https://github.com/rustwasm/wasm-bindgen/issues/111
    #[wasm_bindgen]
    pub fn with_cfrag(&self, cfrag: &CapsuleFrag) -> CapsuleWithFrags {
        CapsuleWithFrags {
            capsule: *self,
            cfrags: vec![*cfrag],
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct CapsuleFrag(GenericArray<u8, <umbral_pre::CapsuleFrag as SerializableToArray>::Size>);

#[wasm_bindgen]
impl CapsuleFrag {
    fn from_backend(cfrag: &umbral_pre::CapsuleFrag) -> Self {
        Self(cfrag.to_array())
    }

    fn to_backend(&self) -> umbral_pre::CapsuleFrag {
        umbral_pre::CapsuleFrag::from_bytes(&self.0).unwrap()
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        capsule: &Capsule,
        signing_pubkey: &UmbralPublicKey,
        delegating_pubkey: &UmbralPublicKey,
        receiving_pubkey: &UmbralPublicKey,
    ) -> bool {
        self.to_backend().verify(
            &capsule.to_backend(),
            &signing_pubkey.to_backend(),
            &delegating_pubkey.to_backend(),
            &receiving_pubkey.to_backend(),
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
        new_cfrags.push(*cfrag);
        Self {
            capsule: self.capsule,
            cfrags: new_cfrags,
        }
    }

    #[wasm_bindgen]
    pub fn decrypt_reencrypted(
        &self,
        decrypting_key: &UmbralSecretKey,
        delegating_pk: &UmbralPublicKey,
        ciphertext: &[u8],
    ) -> Option<Box<[u8]>> {
        let backend_cfrags: Vec<umbral_pre::CapsuleFrag> =
            self.cfrags.iter().map(CapsuleFrag::to_backend).collect();
        umbral_pre::decrypt_reencrypted(
            &decrypting_key.to_backend(),
            &delegating_pk.to_backend(),
            &self.capsule.to_backend(),
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
    params: &UmbralParameters,
    alice_pubkey: &UmbralPublicKey,
    plaintext: &[u8],
) -> EncryptionResult {
    let backend_params = params.to_backend();
    let backend_pubkey = alice_pubkey.to_backend();
    let (capsule, ciphertext) = umbral_pre::encrypt(&backend_params, &backend_pubkey, plaintext);
    EncryptionResult::new(ciphertext, Capsule::from_backend(&capsule))
}

#[wasm_bindgen]
pub fn decrypt_original(
    decrypting_key: &UmbralSecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> Box<[u8]> {
    let backend_capsule = capsule.to_backend();
    let backend_key = decrypting_key.to_backend();
    umbral_pre::decrypt_original(&backend_key, &backend_capsule, ciphertext).unwrap()
}

#[wasm_bindgen]
pub struct KeyFrag(GenericArray<u8, <umbral_pre::KeyFrag as SerializableToArray>::Size>);

#[wasm_bindgen]
impl KeyFrag {
    fn from_backend(kfrag: &umbral_pre::KeyFrag) -> Self {
        Self(kfrag.to_array())
    }

    fn to_backend(&self) -> umbral_pre::KeyFrag {
        umbral_pre::KeyFrag::from_bytes(&self.0).unwrap()
    }

    // FIXME: `Option<&UmbralPublicKey> are currently not supported.
    // See https://github.com/rustwasm/wasm-bindgen/issues/2370
    #[wasm_bindgen]
    pub fn verify(
        &self,
        signing_pubkey: &UmbralPublicKey,
        delegating_pubkey: &UmbralPublicKey,
        receiving_pubkey: &UmbralPublicKey,
    ) -> bool {
        let backend_delegating_pubkey = delegating_pubkey.to_backend();
        let backend_receiving_pubkey = receiving_pubkey.to_backend();

        self.to_backend().verify(
            &signing_pubkey.to_backend(),
            Some(&backend_delegating_pubkey),
            Some(&backend_receiving_pubkey),
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn generate_kfrags(
    params: &UmbralParameters,
    delegating_sk: &UmbralSecretKey,
    receiving_pubkey: &UmbralPublicKey,
    signing_sk: &UmbralSecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<JsValue> {
    let backend_params = params.to_backend();
    let backend_delegating_sk = delegating_sk.to_backend();
    let backend_receiving_pubkey = receiving_pubkey.to_backend();
    let backend_signing_sk = signing_sk.to_backend();
    let backend_kfrags = umbral_pre::generate_kfrags(
        &backend_params,
        &backend_delegating_sk,
        &backend_receiving_pubkey,
        &backend_signing_sk,
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
        .map(|kfrag| KeyFrag::from_backend(&kfrag))
        .map(JsValue::from)
        .collect()
}

#[wasm_bindgen]
pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<Box<[u8]>>) -> CapsuleFrag {
    let backend_kfrag = kfrag.to_backend();
    let backend_capsule = capsule.to_backend();
    let metadata_slice = metadata.as_ref().map(|x| x.as_ref());
    let backend_cfrag = umbral_pre::reencrypt(&backend_capsule, &backend_kfrag, metadata_slice);
    CapsuleFrag::from_backend(&backend_cfrag)
}
