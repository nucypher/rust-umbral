use generic_array::GenericArray;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

use umbral::SerializableToArray;

use std::vec::Vec;

#[wasm_bindgen]
pub struct UmbralSecretKey(
    GenericArray<u8, <umbral::UmbralSecretKey as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl UmbralSecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        console_error_panic_hook::set_once(); // TODO: find a better place to initialize it
        Self(umbral::UmbralSecretKey::random().to_array())
    }

    pub(crate) fn to_backend(&self) -> umbral::UmbralSecretKey {
        umbral::UmbralSecretKey::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct UmbralPublicKey(
    GenericArray<u8, <umbral::UmbralPublicKey as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl UmbralPublicKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn from_secret_key(secret_key: &UmbralSecretKey) -> Self {
        let sk = secret_key.to_backend();
        Self(umbral::UmbralPublicKey::from_secret_key(&sk).to_array())
    }

    pub(crate) fn to_backend(&self) -> umbral::UmbralPublicKey {
        umbral::UmbralPublicKey::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
pub struct UmbralParameters(
    GenericArray<u8, <umbral::UmbralParameters as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl UmbralParameters {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(umbral::UmbralParameters::new().to_array())
    }

    pub(crate) fn to_backend(&self) -> umbral::UmbralParameters {
        umbral::UmbralParameters::from_bytes(&self.0).unwrap()
    }
}

impl Default for UmbralParameters {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Capsule(GenericArray<u8, <umbral::Capsule as SerializableToArray>::Size>);

#[wasm_bindgen]
impl Capsule {
    fn from_backend(capsule: &umbral::Capsule) -> Self {
        Self(capsule.to_array())
    }

    fn to_backend(&self) -> umbral::Capsule {
        umbral::Capsule::from_bytes(&self.0).unwrap()
    }

    #[wasm_bindgen]
    pub fn with_correctness_keys(
        &self,
        delegating: &UmbralPublicKey,
        receiving: &UmbralPublicKey,
        verifying: &UmbralPublicKey,
    ) -> PreparedCapsule {
        let pc = umbral::Capsule::with_correctness_keys(
            &self.to_backend(),
            &delegating.to_backend(),
            &receiving.to_backend(),
            &verifying.to_backend(),
        );

        PreparedCapsule::from_backend(&pc)
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct CapsuleFrag(GenericArray<u8, <umbral::CapsuleFrag as SerializableToArray>::Size>);

#[wasm_bindgen]
impl CapsuleFrag {
    fn from_backend(cfrag: &umbral::CapsuleFrag) -> Self {
        Self(cfrag.to_array())
    }

    fn to_backend(&self) -> umbral::CapsuleFrag {
        umbral::CapsuleFrag::from_bytes(&self.0).unwrap()
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct PreparedCapsule(
    GenericArray<u8, <umbral::PreparedCapsule as SerializableToArray>::Size>,
);

#[wasm_bindgen]
impl PreparedCapsule {
    fn from_backend(capsule: &umbral::PreparedCapsule) -> Self {
        Self(capsule.to_array())
    }

    fn to_backend(&self) -> umbral::PreparedCapsule {
        umbral::PreparedCapsule::from_bytes(&self.0).unwrap()
    }

    #[wasm_bindgen]
    pub fn reencrypt(
        &self,
        kfrag: &KeyFrag,
        metadata: Option<Box<[u8]>>,
        verify_kfrag: bool,
    ) -> Option<CapsuleFrag> {
        let backend_self = self.to_backend();
        let backend_kfrag = kfrag.to_backend();
        if verify_kfrag && !backend_self.verify_kfrag(&backend_kfrag) {
            return None;
        }
        let metadata_slice = metadata.as_ref().map(|x| x.as_ref());

        backend_self
            .reencrypt(&backend_kfrag, metadata_slice, verify_kfrag)
            .map(|x| CapsuleFrag::from_backend(&x))
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
pub struct CapsuleWithFrags {
    capsule: PreparedCapsule,
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
        ciphertext: &[u8],
        decrypting_key: &UmbralSecretKey,
        check_proof: bool,
    ) -> Option<Vec<u8>> {
        let backend_cfrags: Vec<umbral::CapsuleFrag> =
            self.cfrags.iter().map(CapsuleFrag::to_backend).collect();
        umbral::decrypt_reencrypted(
            ciphertext,
            &self.capsule.to_backend(),
            backend_cfrags.as_slice(),
            &decrypting_key.to_backend(),
            check_proof,
        )
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
            ciphertext,
            capsule,
        }
    }

    // FIXME: currently can't just make the field public because `Vec` doesn't implement `Copy`.
    // See https://github.com/rustwasm/wasm-bindgen/issues/439
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

#[wasm_bindgen]
pub struct KeyFrag(GenericArray<u8, <umbral::KeyFrag as SerializableToArray>::Size>);

#[wasm_bindgen]
impl KeyFrag {
    fn from_backend(kfrag: &umbral::KeyFrag) -> Self {
        Self(kfrag.to_array())
    }

    fn to_backend(&self) -> umbral::KeyFrag {
        umbral::KeyFrag::from_bytes(&self.0).unwrap()
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
    delegating_privkey: &UmbralSecretKey,
    receiving_pubkey: &UmbralPublicKey,
    signing_privkey: &UmbralSecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<JsValue> {
    let backend_params = params.to_backend();
    let backend_delegating_privkey = delegating_privkey.to_backend();
    let backend_receiving_pubkey = receiving_pubkey.to_backend();
    let backend_signing_privkey = signing_privkey.to_backend();
    let backend_kfrags = umbral::generate_kfrags(
        &backend_params,
        &backend_delegating_privkey,
        &backend_receiving_pubkey,
        &backend_signing_privkey,
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
