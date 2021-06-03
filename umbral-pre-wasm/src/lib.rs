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
        console_error_panic_hook::set_once(); // TODO (#16): find a better place to initialize it
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
pub struct Signer(umbral_pre::Signer);

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: &SecretKey) -> Self {
        Self(umbral_pre::Signer::new(&secret_key.0))
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }

    pub fn verifying_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }
}

#[wasm_bindgen]
pub struct Signature(umbral_pre::Signature);

#[wasm_bindgen]
impl Signature {
    pub fn verify(&self, verifying_key: &PublicKey, message: &[u8]) -> bool {
        self.0.verify(&verifying_key.0, message)
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Capsule(umbral_pre::Capsule);

#[wasm_bindgen]
impl Capsule {
    // TODO (#23): have to add cfrags one by one since `wasm_bindgen` currently does not support
    // Vec<CustomStruct> as a parameter.
    // Will probably be fixed along with https://github.com/rustwasm/wasm-bindgen/issues/111
    #[wasm_bindgen]
    pub fn with_cfrag(&self, cfrag: &VerifiedCapsuleFrag) -> CapsuleWithFrags {
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
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
        metadata: Option<Box<[u8]>>,
    ) -> VerifiedCapsuleFrag {
        // feels like there should be a better way...
        let metadata_ref: Option<&[u8]> = metadata.as_ref().map(|s| s.as_ref());
        VerifiedCapsuleFrag(
            self.0
                .verify(
                    &capsule.0,
                    &verifying_pk.0,
                    &delegating_pk.0,
                    &receiving_pk.0,
                    metadata_ref,
                )
                .unwrap(),
        )
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct VerifiedCapsuleFrag(umbral_pre::VerifiedCapsuleFrag);

#[wasm_bindgen]
pub struct CapsuleWithFrags {
    capsule: Capsule,
    cfrags: Vec<VerifiedCapsuleFrag>,
}

#[wasm_bindgen]
impl CapsuleWithFrags {
    #[wasm_bindgen]
    pub fn with_cfrag(&self, cfrag: &VerifiedCapsuleFrag) -> CapsuleWithFrags {
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
        decrypting_sk: &SecretKey,
        delegating_pk: &PublicKey,
        ciphertext: &[u8],
    ) -> Option<Box<[u8]>> {
        let backend_cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> =
            self.cfrags.iter().cloned().map(|x| x.0).collect();
        umbral_pre::decrypt_reencrypted(
            &decrypting_sk.0,
            &delegating_pk.0,
            &self.capsule.0,
            backend_cfrags.as_slice(),
            ciphertext,
        )
        .ok()
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

    // TODO (#24): currently can't just make the field public because `Box` doesn't implement `Copy`.
    // See https://github.com/rustwasm/wasm-bindgen/issues/439
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Box<[u8]> {
        self.ciphertext.clone()
    }
}

#[wasm_bindgen]
pub fn encrypt(pk: &PublicKey, plaintext: &[u8]) -> Option<EncryptionResult> {
    let backend_pk = pk.0;
    let (capsule, ciphertext) = umbral_pre::encrypt(&backend_pk, plaintext).unwrap();
    Some(EncryptionResult::new(ciphertext, Capsule(capsule)))
}

#[wasm_bindgen]
pub fn decrypt_original(
    decrypting_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> Box<[u8]> {
    umbral_pre::decrypt_original(&decrypting_sk.0, &capsule.0, ciphertext).unwrap()
}

#[wasm_bindgen]
pub struct KeyFrag(umbral_pre::KeyFrag);

#[wasm_bindgen]
impl KeyFrag {
    // TODO (#25): `Option<&PublicKey> are currently not supported.
    // See https://github.com/rustwasm/wasm-bindgen/issues/2370
    // So we have to use 4 functions instead of 1. Yikes.

    #[wasm_bindgen]
    pub fn verify(&self, verifying_pk: &PublicKey) -> VerifiedKeyFrag {
        VerifiedKeyFrag(self.0.verify(&verifying_pk.0, None, None).unwrap())
    }

    #[wasm_bindgen]
    pub fn verify_with_delegating_key(
        &self,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
    ) -> VerifiedKeyFrag {
        let backend_delegating_pk = delegating_pk.0;

        VerifiedKeyFrag(
            self.0
                .verify(&verifying_pk.0, Some(&backend_delegating_pk), None)
                .unwrap(),
        )
    }

    #[wasm_bindgen]
    pub fn verify_with_receiving_key(
        &self,
        verifying_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> VerifiedKeyFrag {
        let backend_receiving_pk = receiving_pk.0;

        VerifiedKeyFrag(
            self.0
                .verify(&verifying_pk.0, None, Some(&backend_receiving_pk))
                .unwrap(),
        )
    }

    #[wasm_bindgen]
    pub fn verify_with_delegating_and_receiving_keys(
        &self,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> VerifiedKeyFrag {
        let backend_delegating_pk = delegating_pk.0;
        let backend_receiving_pk = receiving_pk.0;

        VerifiedKeyFrag(
            self.0
                .verify(
                    &verifying_pk.0,
                    Some(&backend_delegating_pk),
                    Some(&backend_receiving_pk),
                )
                .unwrap(),
        )
    }
}

#[wasm_bindgen]
pub struct VerifiedKeyFrag(umbral_pre::VerifiedKeyFrag);

#[wasm_bindgen]
impl VerifiedKeyFrag {
    pub fn from_verified_bytes(bytes: &[u8]) -> Self {
        umbral_pre::VerifiedKeyFrag::from_verified_bytes(bytes)
            .map(Self)
            .unwrap()
    }
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn generate_kfrags(
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signer: &Signer,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<JsValue> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &delegating_sk.0,
        &receiving_pk.0,
        &signer.0,
        threshold,
        num_kfrags,
        sign_delegating_key,
        sign_receiving_key,
    );

    // TODO (#26): Apparently we cannot just return a vector of things,
    // so we have to convert them to JsValues manually.
    // See https://github.com/rustwasm/wasm-bindgen/issues/111
    backend_kfrags
        .iter()
        .cloned()
        .map(VerifiedKeyFrag)
        .map(JsValue::from)
        .collect()
}

#[wasm_bindgen]
pub fn reencrypt(
    capsule: &Capsule,
    kfrag: &VerifiedKeyFrag,
    metadata: Option<Box<[u8]>>,
) -> VerifiedCapsuleFrag {
    let metadata_slice = metadata.as_ref().map(|x| x.as_ref());
    let backend_cfrag = umbral_pre::reencrypt(&capsule.0, &kfrag.0, metadata_slice);
    VerifiedCapsuleFrag(backend_cfrag)
}
