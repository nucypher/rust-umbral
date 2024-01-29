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

use js_sys::{Error, Uint8Array};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use wasm_bindgen::JsCast;
use wasm_bindgen_derive::TryFromJsValue;

use crate as umbral_pre;
use crate::{DefaultDeserialize, DefaultSerialize};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "VerifiedCapsuleFrag[]")]
    pub type VerifiedCapsuleFragArray;

    #[wasm_bindgen(typescript_type = "PublicKey | null")]
    pub type OptionPublicKey;

    #[wasm_bindgen(typescript_type = "VerifiedKeyFrag[]")]
    pub type VerifiedKeyFragArray;

    #[wasm_bindgen(typescript_type = "[Capsule, Uint8Array]")]
    pub type EncryptionResult;

    #[wasm_bindgen(typescript_type = "[Uint8Array, Uint8Array]")]
    pub type Coordinates;
}

fn map_js_err<T: fmt::Display>(err: T) -> Error {
    Error::new(&format!("{err}"))
}

/// Tries to convert an optional value (either `null` or a `#[wasm_bindgen]` marked structure)
/// from `JsValue` to the Rust type.
// TODO (#25): This is necessary since wasm-bindgen does not support
// having a parameter of `Option<&T>`, and using `Option<T>` consumes the argument
// (see https://github.com/rustwasm/wasm-bindgen/issues/2370).
fn try_from_js_option<'a, T>(value: &'a JsValue) -> Result<Option<T>, Error>
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

/// Tries to convert a JS array from `JsValue` to a vector of Rust type elements.
// TODO (#23): This is necessary since wasm-bindgen does not support
// having a parameter of `Vec<&T>`
// (see https://github.com/rustwasm/wasm-bindgen/issues/111).
fn try_from_js_array<T>(value: &JsValue) -> Result<Vec<T>, Error>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let array: &js_sys::Array = value
        .dyn_ref()
        .ok_or_else(|| Error::new("Got a non-array argument where an array was expected"))?;
    let length: usize = array.length().try_into().map_err(map_js_err)?;
    let mut result = Vec::<T>::with_capacity(length);
    for js in array.iter() {
        let typed_elem = T::try_from(&js).map_err(map_js_err)?;
        result.push(typed_elem);
    }
    Ok(result)
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

    #[wasm_bindgen(js_name = toBEBytes)]
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        let serialized = self.0.to_be_bytes();
        let bytes: &[u8] = serialized.as_secret().as_ref();
        bytes.into()
    }

    #[wasm_bindgen(js_name = fromBEBytes)]
    pub fn from_be_bytes(data: &[u8]) -> Result<SecretKey, Error> {
        umbral_pre::SecretKey::try_from_be_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    /// Generates a secret key using the default RNG and returns it.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &SecretKey) -> bool {
        self.0 == other.0
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

    #[wasm_bindgen(js_name = makeSecret)]
    pub fn make_secret(&self, label: &[u8]) -> Vec<u8> {
        let secret = self.0.make_secret(label);
        let bytes: &[u8] = secret.as_secret().as_ref();
        bytes.into()
    }

    #[wasm_bindgen(js_name = makeKey)]
    pub fn make_key(&self, label: &[u8]) -> SecretKey {
        SecretKey(self.0.make_key(label))
    }

    #[wasm_bindgen(js_name = makeFactory)]
    pub fn make_factory(&self, label: &[u8]) -> Self {
        Self(self.0.make_factory(label))
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct PublicKey(umbral_pre::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = toCompressedBytes)]
    pub fn to_compressed_bytes(&self) -> Box<[u8]> {
        self.0.to_compressed_bytes()
    }

    #[wasm_bindgen(js_name = fromCompressedBytes)]
    pub fn from_compressed_bytes(data: &[u8]) -> Result<PublicKey, Error> {
        umbral_pre::PublicKey::try_from_compressed_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = recoverFromPrehash)]
    pub fn recover_from_prehash(
        prehash: &[u8],
        signature: &RecoverableSignature,
    ) -> Result<PublicKey, Error> {
        umbral_pre::PublicKey::recover_from_prehash(prehash, &signature.0)
            .map(Self)
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

    #[wasm_bindgen(js_name = toDerBytes)]
    pub fn to_der_bytes(&self) -> Box<[u8]> {
        self.0.to_der_bytes()
    }

    #[wasm_bindgen(js_name = fromDerBytes)]
    pub fn from_der_bytes(data: &[u8]) -> Result<Signature, Error> {
        umbral_pre::Signature::try_from_der_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBEBytes)]
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        self.0.to_be_bytes()
    }

    #[wasm_bindgen(js_name = fromBEBytes)]
    pub fn from_be_bytes(data: &[u8]) -> Result<Signature, Error> {
        umbral_pre::Signature::try_from_be_bytes(data)
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
#[derive(derive_more::AsRef, derive_more::From)]
pub struct RecoverableSignature(umbral_pre::RecoverableSignature);

#[wasm_bindgen]
impl RecoverableSignature {
    #[wasm_bindgen(js_name = toBEBytes)]
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        self.0.to_be_bytes()
    }

    #[wasm_bindgen(js_name = fromBEBytes)]
    pub fn from_be_bytes(data: &[u8]) -> Result<RecoverableSignature, Error> {
        umbral_pre::RecoverableSignature::try_from_be_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    pub fn equals(&self, other: &RecoverableSignature) -> bool {
        self.0 == other.0
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct Capsule(umbral_pre::Capsule);

#[wasm_bindgen]
impl Capsule {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
        self.0.to_bytes().map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytesSimple)]
    pub fn to_bytes_simple(&self) -> Box<[u8]> {
        self.0.to_bytes_simple()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<Capsule, Error> {
        umbral_pre::Capsule::from_bytes(data)
            .map(Self)
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
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
        self.0.to_bytes().map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytesSimple)]
    pub fn to_bytes_simple(&self) -> Box<[u8]> {
        self.0.to_bytes_simple()
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

    #[wasm_bindgen(js_name = skipVerification)]
    pub fn skip_verification(&self) -> VerifiedCapsuleFrag {
        VerifiedCapsuleFrag(self.0.clone().skip_verification())
    }

    pub fn equals(&self, other: &CapsuleFrag) -> bool {
        self.0 == other.0
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct VerifiedCapsuleFrag(umbral_pre::VerifiedCapsuleFrag);

#[wasm_bindgen]
impl VerifiedCapsuleFrag {
    pub fn unverify(&self) -> CapsuleFrag {
        CapsuleFrag(self.0.clone().unverify())
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
        self.0.to_bytes().map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytesSimple)]
    pub fn to_bytes_simple(&self) -> Box<[u8]> {
        self.0.to_bytes_simple()
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
pub fn encrypt(delegating_pk: &PublicKey, plaintext: &[u8]) -> Result<EncryptionResult, Error> {
    let backend_pk = delegating_pk.0;
    let (capsule, ciphertext) = umbral_pre::encrypt(&backend_pk, plaintext).map_err(map_js_err)?;

    // TODO (#24): wasm-bindgen does not allow one to return a tuple directly.
    // Have to cast it manually.
    let capsule_js: JsValue = Capsule::from(capsule).into();
    let ciphertext_js: JsValue = Uint8Array::from(ciphertext.as_ref()).into();
    Ok([capsule_js, ciphertext_js]
        .into_iter()
        .collect::<js_sys::Array>()
        .unchecked_into::<EncryptionResult>())
}

#[wasm_bindgen(js_name = decryptOriginal)]
pub fn decrypt_original(
    delegating_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> Result<Box<[u8]>, Error> {
    umbral_pre::decrypt_original(&delegating_sk.0, &capsule.0, ciphertext).map_err(map_js_err)
}

#[wasm_bindgen(js_name = decryptReencrypted)]
pub fn decrypt_reencrypted(
    receiving_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    vcfrags: &VerifiedCapsuleFragArray,
    ciphertext: &[u8],
) -> Result<Box<[u8]>, Error> {
    // TODO (#23): using a custom type since `wasm_bindgen` currently does not support
    // Vec<CustomStruct> as a parameter.
    // Will probably be fixed along with https://github.com/rustwasm/wasm-bindgen/issues/111
    let typed_vcfrags = try_from_js_array::<VerifiedCapsuleFrag>(vcfrags.as_ref())?;
    let backend_vcfrags = typed_vcfrags.into_iter().map(|vcfrag| vcfrag.0);
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
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
        self.0.to_bytes().map_err(map_js_err)
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

    #[wasm_bindgen(js_name = skipVerification)]
    pub fn skip_verification(&self) -> VerifiedKeyFrag {
        VerifiedKeyFrag(self.0.clone().skip_verification())
    }

    pub fn equals(&self, other: &KeyFrag) -> bool {
        self.0 == other.0
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct VerifiedKeyFrag(umbral_pre::VerifiedKeyFrag);

#[wasm_bindgen]
impl VerifiedKeyFrag {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
        self.0.to_bytes().map_err(map_js_err)
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
        .into_vec()
        .into_iter()
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

#[wasm_bindgen]
pub struct CurvePoint(umbral_pre::CurvePoint);

#[wasm_bindgen]
impl CurvePoint {
    #[wasm_bindgen]
    pub fn coordinates(&self) -> Option<Coordinates> {
        let (x, y) = self.0.coordinates()?;
        let x_js: JsValue = Uint8Array::from(x.as_ref()).into();
        let y_js: JsValue = Uint8Array::from(y.as_ref()).into();
        Some(
            [x_js, y_js]
                .into_iter()
                .collect::<js_sys::Array>()
                .unchecked_into::<Coordinates>(),
        )
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

    #[wasm_bindgen(getter)]
    pub fn u(&self) -> CurvePoint {
        CurvePoint(self.0.u)
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct ReencryptionEvidence(umbral_pre::ReencryptionEvidence);

#[wasm_bindgen]
impl ReencryptionEvidence {
    #[wasm_bindgen(constructor)]
    pub fn new(
        capsule: &Capsule,
        vcfrag: &VerifiedCapsuleFrag,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Result<ReencryptionEvidence, Error> {
        umbral_pre::ReencryptionEvidence::new(
            &capsule.0,
            &vcfrag.0,
            &verifying_pk.0,
            &delegating_pk.0,
            &receiving_pk.0,
        )
        .map(Self)
        .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
        self.0.to_bytes().map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<ReencryptionEvidence, Error> {
        umbral_pre::ReencryptionEvidence::from_bytes(data)
            .map(Self)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(getter)]
    pub fn e(&self) -> CurvePoint {
        CurvePoint(self.0.e)
    }

    #[wasm_bindgen(getter)]
    pub fn ez(&self) -> CurvePoint {
        CurvePoint(self.0.ez)
    }

    #[wasm_bindgen(getter)]
    pub fn e1(&self) -> CurvePoint {
        CurvePoint(self.0.e1)
    }

    #[wasm_bindgen(getter)]
    pub fn e1h(&self) -> CurvePoint {
        CurvePoint(self.0.e1h)
    }

    #[wasm_bindgen(getter)]
    pub fn e2(&self) -> CurvePoint {
        CurvePoint(self.0.e2)
    }

    #[wasm_bindgen(getter)]
    pub fn v(&self) -> CurvePoint {
        CurvePoint(self.0.v)
    }

    #[wasm_bindgen(getter)]
    pub fn vz(&self) -> CurvePoint {
        CurvePoint(self.0.vz)
    }

    #[wasm_bindgen(getter)]
    pub fn v1(&self) -> CurvePoint {
        CurvePoint(self.0.v1)
    }

    #[wasm_bindgen(getter)]
    pub fn v1h(&self) -> CurvePoint {
        CurvePoint(self.0.v1h)
    }

    #[wasm_bindgen(getter)]
    pub fn v2(&self) -> CurvePoint {
        CurvePoint(self.0.v2)
    }

    #[wasm_bindgen(getter)]
    pub fn uz(&self) -> CurvePoint {
        CurvePoint(self.0.uz)
    }

    #[wasm_bindgen(getter)]
    pub fn u1(&self) -> CurvePoint {
        CurvePoint(self.0.u1)
    }

    #[wasm_bindgen(getter)]
    pub fn u1h(&self) -> CurvePoint {
        CurvePoint(self.0.u1h)
    }

    #[wasm_bindgen(getter)]
    pub fn u2(&self) -> CurvePoint {
        CurvePoint(self.0.u2)
    }

    #[wasm_bindgen(getter, js_name = kfragValidityMessageHash)]
    pub fn kfrag_validity_message_hash(&self) -> Uint8Array {
        Uint8Array::from(self.0.kfrag_validity_message_hash.as_ref())
    }

    #[wasm_bindgen(getter, js_name = kfragSignatureV)]
    pub fn kfrag_signature_v(&self) -> bool {
        self.0.kfrag_signature_v
    }
}
