extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::{vec, vec::Vec};
use core::fmt;

use js_sys::Error;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

use serde::{Deserialize, Serialize};

use crate as umbral_pre;
use crate::{DeserializableFromArray, SerializableToArray, SerializableToSecretArray};

fn map_js_err<T: fmt::Display>(err: T) -> JsValue {
    Error::new(&format!("{}", err)).into()
}

#[wasm_bindgen]
pub struct SecretKey {
    backend: umbral_pre::SecretKey,
}

#[wasm_bindgen]
impl SecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        Self {
            backend: umbral_pre::SecretKey::random(),
        }
    }

    /// Generates a secret key using the default RNG and returns it.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.public_key(),
        }
    }

    #[wasm_bindgen(js_name = toSecretBytes)]
    pub fn to_secret_bytes(&self) -> Box<[u8]> {
        self.backend
            .to_secret_array()
            .as_secret()
            .to_vec()
            .into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<SecretKey, JsValue> {
        umbral_pre::SecretKey::from_bytes(data)
            .map(|sk| Self { backend: sk })
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.backend)
    }
}

impl SecretKey {
    pub fn inner(&self) -> &umbral_pre::SecretKey {
        &self.backend
    }
}

#[wasm_bindgen]
pub struct SecretKeyFactory(umbral_pre::SecretKeyFactory);

#[wasm_bindgen]
impl SecretKeyFactory {
    /// Generates a secret key factory using the default RNG and returns it.
    pub fn random() -> Self {
        Self(umbral_pre::SecretKeyFactory::random())
    }

    #[wasm_bindgen(js_name = seedSize)]
    pub fn seed_size() -> usize {
        umbral_pre::SecretKeyFactory::seed_size()
    }

    #[wasm_bindgen(js_name = fromSecureRandomness)]
    pub fn from_secure_randomness(seed: &[u8]) -> Result<SecretKeyFactory, JsValue> {
        umbral_pre::SecretKeyFactory::from_secure_randomness(seed)
            .map(Self)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = makeKey)]
    pub fn make_key(&self, label: &[u8]) -> Result<SecretKey, JsValue> {
        self.0
            .make_key(label)
            .map(|sk| SecretKey { backend: sk })
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = makeFactory)]
    pub fn make_factory(&self, label: &[u8]) -> Self {
        Self(self.0.make_factory(label))
    }

    #[wasm_bindgen(js_name = toSecretBytes)]
    pub fn to_secret_bytes(&self) -> Box<[u8]> {
        self.0
            .to_secret_array()
            .as_secret()
            .to_vec()
            .into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<SecretKeyFactory, JsValue> {
        umbral_pre::SecretKeyFactory::from_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    backend: umbral_pre::PublicKey,
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.backend.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<PublicKey, JsValue> {
        umbral_pre::PublicKey::from_bytes(data)
            .map(PublicKey::new)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.backend)
    }

    pub fn equals(&self, other: &PublicKey) -> bool {
        self.backend == other.backend
    }
}

impl PublicKey {
    pub fn new(public_key: umbral_pre::PublicKey) -> Self {
        PublicKey {
            backend: public_key,
        }
    }

    pub fn inner(&self) -> &umbral_pre::PublicKey {
        &self.backend
    }
}

#[wasm_bindgen]
pub struct Signer(umbral_pre::Signer);

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: &SecretKey) -> Self {
        Self(umbral_pre::Signer::new(&secret_key.backend))
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey {
            backend: self.0.verifying_key(),
        }
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

impl Signer {
    pub fn inner(&self) -> &umbral_pre::Signer {
        &self.0
    }
}

#[wasm_bindgen]
pub struct Signature(umbral_pre::Signature);

#[wasm_bindgen]
impl Signature {
    pub fn verify(&self, verifying_pk: &PublicKey, message: &[u8]) -> bool {
        self.0.verify(&verifying_pk.backend, message)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<Signature, JsValue> {
        umbral_pre::Signature::from_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &Signature) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Capsule {
    backend: umbral_pre::Capsule,
}

#[wasm_bindgen]
impl Capsule {
    // TODO (#23): have to add cfrags one by one since `wasm_bindgen` currently does not support
    // Vec<CustomStruct> as a parameter.
    // Will probably be fixed along with https://github.com/rustwasm/wasm-bindgen/issues/111
    #[wasm_bindgen(js_name = withCFrag)]
    pub fn with_cfrag(&self, cfrag: &VerifiedCapsuleFrag) -> CapsuleWithFrags {
        CapsuleWithFrags {
            capsule: *self,
            cfrags: vec![cfrag.clone()],
        }
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.backend.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<Capsule, JsValue> {
        umbral_pre::Capsule::from_bytes(data)
            .map(Capsule::new)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.backend)
    }

    pub fn equals(&self, other: &Capsule) -> bool {
        self.backend == other.backend
    }
}

impl Capsule {
    pub fn new(capsule: umbral_pre::Capsule) -> Capsule {
        Capsule { backend: capsule }
    }

    pub fn inner(&self) -> &umbral_pre::Capsule {
        &self.backend
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
    ) -> Result<VerifiedCapsuleFrag, JsValue> {
        self.0
            .verify(
                &capsule.backend,
                &verifying_pk.backend,
                &delegating_pk.backend,
                &receiving_pk.backend,
            )
            .map(VerifiedCapsuleFrag::new)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<CapsuleFrag, JsValue> {
        umbral_pre::CapsuleFrag::from_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &CapsuleFrag) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct VerifiedCapsuleFrag {
    backend: umbral_pre::VerifiedCapsuleFrag,
}

#[wasm_bindgen]
impl VerifiedCapsuleFrag {
    #[wasm_bindgen(js_name = fromVerifiedBytes)]
    pub fn from_verified_bytes(bytes: &[u8]) -> Result<VerifiedCapsuleFrag, JsValue> {
        umbral_pre::VerifiedCapsuleFrag::from_verified_bytes(bytes)
            .map(|vcfrag| VerifiedCapsuleFrag { backend: vcfrag })
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.backend.to_array().to_vec().into_boxed_slice()
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.backend)
    }

    pub fn equals(&self, other: &VerifiedCapsuleFrag) -> bool {
        self.backend == other.backend
    }
}

impl VerifiedCapsuleFrag {
    pub fn new(vcfrag: umbral_pre::VerifiedCapsuleFrag) -> Self {
        Self { backend: vcfrag }
    }

    pub fn inner(&self) -> umbral_pre::VerifiedCapsuleFrag {
        self.backend.clone()
    }
}

#[wasm_bindgen]
pub struct CapsuleWithFrags {
    capsule: Capsule,
    cfrags: Vec<VerifiedCapsuleFrag>,
}

#[wasm_bindgen]
impl CapsuleWithFrags {
    #[wasm_bindgen(js_name = withCFrag)]
    pub fn with_cfrag(&self, cfrag: &VerifiedCapsuleFrag) -> CapsuleWithFrags {
        let mut new_cfrags = self.cfrags.clone();
        new_cfrags.push(cfrag.clone());
        Self {
            capsule: self.capsule,
            cfrags: new_cfrags,
        }
    }

    #[wasm_bindgen(js_name = decryptReencrypted)]
    pub fn decrypt_reencrypted(
        &self,
        receiving_sk: &SecretKey,
        delegating_pk: &PublicKey,
        ciphertext: &[u8],
    ) -> Result<Box<[u8]>, JsValue> {
        let backend_cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> =
            self.cfrags.iter().cloned().map(|x| x.backend).collect();
        umbral_pre::decrypt_reencrypted(
            &receiving_sk.backend,
            &delegating_pk.backend,
            &self.capsule.backend,
            backend_cfrags.as_slice(),
            ciphertext,
        )
        .map_err(map_js_err)
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
pub fn encrypt(delegating_pk: &PublicKey, plaintext: &[u8]) -> Result<EncryptionResult, JsValue> {
    let backend_pk = delegating_pk.backend;
    umbral_pre::encrypt(&backend_pk, plaintext)
        .map(|(capsule, ciphertext)| EncryptionResult::new(ciphertext, Capsule::new(capsule)))
        .map_err(map_js_err)
}

#[wasm_bindgen(js_name = decryptOriginal)]
pub fn decrypt_original(
    delegating_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> Result<Box<[u8]>, JsValue> {
    umbral_pre::decrypt_original(&delegating_sk.backend, &capsule.backend, ciphertext)
        .map_err(map_js_err)
}

#[wasm_bindgen]
pub struct KeyFrag(umbral_pre::KeyFrag);

#[wasm_bindgen]
impl KeyFrag {
    // TODO (#25): `Option<&PublicKey> are currently not supported.
    // See https://github.com/rustwasm/wasm-bindgen/issues/2370
    // So we have to use 4 functions instead of 1. Yikes.

    #[wasm_bindgen]
    pub fn verify(&self, verifying_pk: &PublicKey) -> Result<VerifiedKeyFrag, JsValue> {
        self.0
            .verify(&verifying_pk.backend, None, None)
            .map(VerifiedKeyFrag::new)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = verifyWithDelegatingKey)]
    pub fn verify_with_delegating_key(
        &self,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
    ) -> Result<VerifiedKeyFrag, JsValue> {
        let backend_delegating_pk = delegating_pk.backend;

        self.0
            .verify(&verifying_pk.backend, Some(&backend_delegating_pk), None)
            .map(VerifiedKeyFrag::new)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = verifyWithReceivingKey)]
    pub fn verify_with_receiving_key(
        &self,
        verifying_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Result<VerifiedKeyFrag, JsValue> {
        let backend_receiving_pk = receiving_pk.backend;

        self.0
            .verify(&verifying_pk.backend, None, Some(&backend_receiving_pk))
            .map(VerifiedKeyFrag::new)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = verifyWithDelegatingAndReceivingKeys)]
    pub fn verify_with_delegating_and_receiving_keys(
        &self,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Result<VerifiedKeyFrag, JsValue> {
        let backend_delegating_pk = delegating_pk.backend;
        let backend_receiving_pk = receiving_pk.backend;

        self.0
            .verify(
                &verifying_pk.backend,
                Some(&backend_delegating_pk),
                Some(&backend_receiving_pk),
            )
            .map(VerifiedKeyFrag::new)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<KeyFrag, JsValue> {
        umbral_pre::KeyFrag::from_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &KeyFrag) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone)]
pub struct VerifiedKeyFrag {
    backend: umbral_pre::VerifiedKeyFrag,
}

#[wasm_bindgen]
impl VerifiedKeyFrag {
    #[wasm_bindgen(js_name = fromVerifiedBytes)]
    pub fn from_verified_bytes(bytes: &[u8]) -> Result<VerifiedKeyFrag, JsValue> {
        umbral_pre::VerifiedKeyFrag::from_verified_bytes(bytes)
            .map(VerifiedKeyFrag::new)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.backend.to_array().to_vec().into_boxed_slice()
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.backend)
    }

    pub fn equals(&self, other: &VerifiedKeyFrag) -> bool {
        self.backend == other.backend
    }
}

impl VerifiedKeyFrag {
    pub fn new(vkfrag: umbral_pre::VerifiedKeyFrag) -> VerifiedKeyFrag {
        VerifiedKeyFrag { backend: vkfrag }
    }

    pub fn inner(&self) -> &umbral_pre::VerifiedKeyFrag {
        &self.backend
    }
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = generateKFrags)]
pub fn generate_kfrags(
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signer: &Signer,
    threshold: usize,
    shares: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<JsValue> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &delegating_sk.backend,
        &receiving_pk.backend,
        &signer.0,
        threshold,
        shares,
        sign_delegating_key,
        sign_receiving_key,
    );

    // TODO (#26): Apparently we cannot just return a vector of things,
    // so we have to convert them to JsValues manually.
    // See https://github.com/rustwasm/wasm-bindgen/issues/111
    backend_kfrags
        .iter()
        .cloned()
        .map(VerifiedKeyFrag::new)
        .map(JsValue::from)
        .collect()
}

#[wasm_bindgen]
pub fn reencrypt(capsule: &Capsule, kfrag: &VerifiedKeyFrag) -> VerifiedCapsuleFrag {
    let vcfrag = umbral_pre::reencrypt(&capsule.backend, &kfrag.backend);
    VerifiedCapsuleFrag::new(vcfrag)
}
