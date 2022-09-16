// Disable false-positive warnings caused by `#[wasm-bindgen]` on struct impls
#![allow(clippy::unused_unit)]

//! Type wrappers for WASM bindings.

// TODO: Write the docs
#![allow(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use js_sys::Error;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use wasm_bindgen::JsCast;
use wasm_bindgen_derive::TryFromJsValue;

use serde::{Deserialize, Serialize};

use crate as umbral_pre;
use crate::{DeserializableFromArray, SerializableToArray, SerializableToSecretArray};

fn map_js_err<T: fmt::Display>(err: T) -> Error {
    Error::new(&format!("{}", err))
}

/// Tries to convert an optional value (either `null` or a `#[wasm_bindgen]` marked structure)
/// from `JsValue` to the Rust type.
// This is necessary since wasm-bindgen does not support having a paramter of `Option<&T>`,
// and using `Option<T>` consumes the argument
// (see https://github.com/rustwasm/wasm-bindgen/issues/2370).
fn try_from_js_option<'a, T>(value: &'a JsValue) -> Result<Option<T>, JsValue>
where
    T: TryFrom<&'a JsValue>,
    <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let typed_value = if value.is_null() {
        None
    } else {
        Some(T::try_from(value).map_err(map_js_err)?)
    };
    Ok(typed_value)
}

#[wasm_bindgen]
#[derive(derive_more::AsRef)]
pub struct SecretKey(umbral_pre::SecretKey);

#[wasm_bindgen]
impl SecretKey {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        Self(umbral_pre::SecretKey::random())
    }

    /// Generates a secret key using the default RNG and returns it.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
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
    pub fn from_bytes(data: &[u8]) -> Result<SecretKey, Error> {
        umbral_pre::SecretKey::from_bytes(data)
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
    pub fn from_secure_randomness(seed: &[u8]) -> Result<SecretKeyFactory, Error> {
        umbral_pre::SecretKeyFactory::from_secure_randomness(seed)
            .map(Self)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = makeKey)]
    pub fn make_key(&self, label: &[u8]) -> SecretKey {
        SecretKey(self.0.make_key(label))
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
    pub fn from_bytes(data: &[u8]) -> Result<SecretKeyFactory, Error> {
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

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize, derive_more::AsRef, derive_more::From)]
pub struct PublicKey(umbral_pre::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<PublicKey, Error> {
        umbral_pre::PublicKey::from_bytes(data)
            .map(PublicKey)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &PublicKey) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
#[derive(derive_more::AsRef)]
pub struct Signer(umbral_pre::Signer);

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: &SecretKey) -> Self {
        Self(umbral_pre::Signer::new(secret_key.0.clone()))
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

#[wasm_bindgen]
pub struct Signature(umbral_pre::Signature);

#[wasm_bindgen]
impl Signature {
    pub fn verify(&self, verifying_pk: &PublicKey, message: &[u8]) -> bool {
        self.0.verify(&verifying_pk.0, message)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<Signature, Error> {
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
#[derive(Clone, Copy, Serialize, Deserialize, derive_more::AsRef, derive_more::From)]
pub struct Capsule(umbral_pre::Capsule);

#[wasm_bindgen]
impl Capsule {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<Capsule, Error> {
        umbral_pre::Capsule::from_bytes(data)
            .map(Capsule)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &Capsule) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CapsuleFrag(umbral_pre::CapsuleFrag);

#[wasm_bindgen]
impl CapsuleFrag {
    #[wasm_bindgen]
    pub fn verify(
        self,
        capsule: &Capsule,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Result<VerifiedCapsuleFrag, Error> {
        self.0
            .verify(
                &capsule.0,
                &verifying_pk.0,
                &delegating_pk.0,
                &receiving_pk.0,
            )
            .map(VerifiedCapsuleFrag)
            .map_err(|(err, _)| err)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<CapsuleFrag, Error> {
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

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(
    Clone, Serialize, Deserialize, PartialEq, Debug, derive_more::AsRef, derive_more::From,
)]
pub struct VerifiedCapsuleFrag(umbral_pre::VerifiedCapsuleFrag);

#[wasm_bindgen]
impl VerifiedCapsuleFrag {
    #[wasm_bindgen(js_name = fromVerifiedBytes)]
    pub fn from_verified_bytes(bytes: &[u8]) -> Result<VerifiedCapsuleFrag, Error> {
        umbral_pre::VerifiedCapsuleFrag::from_verified_bytes(bytes)
            .map(VerifiedCapsuleFrag)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &VerifiedCapsuleFrag) -> bool {
        self.0 == other.0
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
pub fn encrypt(delegating_pk: &PublicKey, plaintext: &[u8]) -> Result<EncryptionResult, Error> {
    let backend_pk = delegating_pk.0;
    umbral_pre::encrypt(&backend_pk, plaintext)
        .map(|(capsule, ciphertext)| EncryptionResult::new(ciphertext, Capsule(capsule)))
        .map_err(map_js_err)
}

#[wasm_bindgen(js_name = decryptOriginal)]
pub fn decrypt_original(
    delegating_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> Result<Box<[u8]>, Error> {
    umbral_pre::decrypt_original(&delegating_sk.0, &capsule.0, ciphertext).map_err(map_js_err)
}

// TODO (#23): using a custom type since `wasm_bindgen` currently does not support
// Vec<CustomStruct> as a parameter.
// Will probably be fixed along with https://github.com/rustwasm/wasm-bindgen/issues/111
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "VerifiedCapsuleFrag[]")]
    pub type VerifiedCapsuleFragArray;
}

#[wasm_bindgen(js_name = decryptReencrypted)]
pub fn decrypt_reencrypted(
    receiving_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    vcfrags: &VerifiedCapsuleFragArray,
    ciphertext: &[u8],
) -> Result<Box<[u8]>, Error> {
    let js_val = vcfrags.as_ref();
    if !js_sys::Array::is_array(js_val) {
        return Err(Error::new("`vcfrags` must be an array"));
    }
    let array = js_sys::Array::from(js_val);
    let length: usize = array.length().try_into().map_err(map_js_err)?;
    let mut backend_vcfrags = Vec::<umbral_pre::VerifiedCapsuleFrag>::with_capacity(length);
    for js in array.iter() {
        let typed_vcfrag = VerifiedCapsuleFrag::try_from(&js).map_err(map_js_err)?;
        backend_vcfrags.push(typed_vcfrag.0);
    }
    umbral_pre::decrypt_reencrypted(
        &receiving_sk.0,
        &delegating_pk.0,
        &capsule.0,
        backend_vcfrags,
        ciphertext,
    )
    .map_err(map_js_err)
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "PublicKey | null")]
    pub type OptionPublicKey;
}

#[wasm_bindgen]
pub struct KeyFrag(umbral_pre::KeyFrag);

#[wasm_bindgen]
impl KeyFrag {
    #[wasm_bindgen]
    pub fn verify(
        self,
        verifying_pk: &PublicKey,
        // TODO: replace with `Option<&PublicKey>` when `wasm-bindgen` supports it.
        // See https://github.com/rustwasm/wasm-bindgen/issues/2370
        delegating_pk: &OptionPublicKey,
        receiving_pk: &OptionPublicKey,
    ) -> Result<VerifiedKeyFrag, Error> {
        let typed_delegating_pk = try_from_js_option::<PublicKey>(delegating_pk.as_ref())?;
        let typed_receiving_pk = try_from_js_option::<PublicKey>(receiving_pk.as_ref())?;

        self.0
            .verify(
                &verifying_pk.0,
                typed_delegating_pk.as_ref().map(|pk| &pk.0),
                typed_receiving_pk.as_ref().map(|pk| &pk.0),
            )
            .map(VerifiedKeyFrag)
            .map_err(|(err, _)| err)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<KeyFrag, Error> {
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
#[derive(Serialize, Deserialize, Clone, derive_more::AsRef, derive_more::From)]
pub struct VerifiedKeyFrag(umbral_pre::VerifiedKeyFrag);

#[wasm_bindgen]
impl VerifiedKeyFrag {
    #[wasm_bindgen(js_name = fromVerifiedBytes)]
    pub fn from_verified_bytes(bytes: &[u8]) -> Result<VerifiedKeyFrag, Error> {
        umbral_pre::VerifiedKeyFrag::from_verified_bytes(bytes)
            .map(VerifiedKeyFrag)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_array().to_vec().into_boxed_slice()
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &VerifiedKeyFrag) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "VerifiedKeyFrag[]")]
    pub type VerifiedKeyFragArray;
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
) -> VerifiedKeyFragArray {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &delegating_sk.0,
        &receiving_pk.0,
        &signer.0,
        threshold,
        shares,
        sign_delegating_key,
        sign_receiving_key,
    );

    // TODO (#26): Apparently we cannot just return a vector of things,
    // so we have to convert them to JsValues manually and use a custom return type
    // to generate a correct signature for TypeScript.
    // See https://github.com/rustwasm/wasm-bindgen/issues/111
    backend_kfrags
        .iter()
        .cloned()
        .map(VerifiedKeyFrag)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<VerifiedKeyFragArray>()
}

#[wasm_bindgen]
pub fn reencrypt(capsule: &Capsule, kfrag: &VerifiedKeyFrag) -> VerifiedCapsuleFrag {
    let vcfrag = umbral_pre::reencrypt(&capsule.0, kfrag.0.clone());
    VerifiedCapsuleFrag(vcfrag)
}
