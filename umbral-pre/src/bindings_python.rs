//! Type wrappers and a module builder for Python bindings.

// TODO (#30): ideally, we would write documentation for the bindings as docstrings here,
// and let Sphinx pick it up... but it's not great at doing so.
#![allow(missing_docs)]
// Clippy shows false positives in PyO3 methods.
// See https://github.com/rust-lang/rust-clippy/issues/8971
// Will probably be fixed by Rust 1.65
#![allow(clippy::borrow_deref_ref)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use pyo3::class::basic::CompareOp;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pyclass::PyClass;
use pyo3::types::{PyBytes, PyUnicode};
use pyo3::wrap_pyfunction;

use crate as umbral_pre;
use crate::{
    DeserializableFromArray, HasTypeName, RepresentableAsArray, SerializableToArray,
    SerializableToSecretArray,
};

fn to_bytes<T, U>(obj: &T) -> PyResult<PyObject>
where
    T: AsRef<U>,
    U: SerializableToArray,
{
    let serialized = obj.as_ref().to_array();
    Python::with_gil(|py| -> PyResult<PyObject> {
        Ok(PyBytes::new(py, serialized.as_slice()).into())
    })
}

// Can't keep the secret in Python anymore, so this function does the same as `to_bytes()`
fn to_secret_bytes<T, U>(obj: &T) -> PyResult<PyObject>
where
    T: AsRef<U>,
    U: SerializableToSecretArray,
{
    // Dereferencing a secret.
    let serialized = obj.as_ref().to_secret_array().as_secret().clone();
    Python::with_gil(|py| -> PyResult<PyObject> {
        Ok(PyBytes::new(py, serialized.as_slice()).into())
    })
}

fn from_bytes<T, U>(data: &[u8]) -> PyResult<T>
where
    T: From<U>,
    U: DeserializableFromArray + HasTypeName,
{
    U::from_bytes(data)
        .map(T::from)
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

fn hash<T, U>(obj: &T) -> PyResult<isize>
where
    T: AsRef<U>,
    U: SerializableToArray + HasTypeName,
{
    let serialized = obj.as_ref().to_array();

    // call `hash((class_name, bytes(obj)))`
    Python::with_gil(|py| {
        let builtins = PyModule::import(py, "builtins")?;
        let arg1 = PyUnicode::new(py, U::type_name());
        let arg2: PyObject = PyBytes::new(py, serialized.as_slice()).into();
        builtins.getattr("hash")?.call1(((arg1, arg2),))?.extract()
    })
}

fn richcmp<T, U>(obj: &T, other: &T, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq + AsRef<U>,
    U: HasTypeName,
{
    match op {
        CompareOp::Eq => Ok(obj == other),
        CompareOp::Ne => Ok(obj != other),
        _ => Err(PyTypeError::new_err(format!(
            "{} objects are not ordered",
            U::type_name()
        ))),
    }
}

create_exception!(umbral, VerificationError, PyException);

#[pyclass(module = "umbral")]
#[derive(derive_more::AsRef, derive_more::From)]
pub struct SecretKey {
    backend: umbral_pre::SecretKey,
}

#[pymethods]
impl SecretKey {
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            backend: umbral_pre::SecretKey::random(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.public_key(),
        }
    }

    pub fn to_secret_bytes(&self) -> PyResult<PyObject> {
        to_secret_bytes(self)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::SecretKey>(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::SecretKey::serialized_size()
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(derive_more::AsRef, derive_more::From)]
pub struct SecretKeyFactory {
    backend: umbral_pre::SecretKeyFactory,
}

#[pymethods]
impl SecretKeyFactory {
    #[staticmethod]
    pub fn random() -> Self {
        umbral_pre::SecretKeyFactory::random().into()
    }

    #[staticmethod]
    pub fn seed_size() -> usize {
        umbral_pre::SecretKeyFactory::seed_size()
    }

    #[staticmethod]
    pub fn from_secure_randomness(seed: &[u8]) -> PyResult<SecretKeyFactory> {
        umbral_pre::SecretKeyFactory::from_secure_randomness(seed)
            .map(SecretKeyFactory::from)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    pub fn make_key(&self, label: &[u8]) -> SecretKey {
        self.backend.make_key(label).into()
    }

    pub fn make_factory(&self, label: &[u8]) -> Self {
        self.backend.make_factory(label).into()
    }

    pub fn to_secret_bytes(&self) -> PyResult<PyObject> {
        to_secret_bytes(self)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::SecretKeyFactory>(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::SecretKeyFactory::serialized_size()
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(Clone, PartialEq, Eq, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct PublicKey {
    backend: umbral_pre::PublicKey,
}

#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::PublicKey>(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::PublicKey::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(derive_more::AsRef, derive_more::From)]
pub struct Signer {
    backend: umbral_pre::Signer,
}

#[pymethods]
impl Signer {
    #[new]
    pub fn new(sk: &SecretKey) -> Self {
        umbral_pre::Signer::new(sk.backend.clone()).into()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.backend.sign(message).into()
    }

    pub fn verifying_key(&self) -> PublicKey {
        self.backend.verifying_key().into()
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(PartialEq, Eq, derive_more::AsRef, derive_more::From)]
pub struct Signature {
    backend: umbral_pre::Signature,
}

#[pymethods]
impl Signature {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::Signature>(data)
    }

    pub fn verify(&self, verifying_pk: &PublicKey, message: &[u8]) -> bool {
        self.backend.verify(&verifying_pk.backend, message)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::Signature::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(Clone, PartialEq, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct Capsule {
    backend: umbral_pre::Capsule,
}

#[pymethods]
impl Capsule {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::Capsule>(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::Capsule::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyfunction]
pub fn encrypt(
    py: Python<'_>,
    delegating_pk: &PublicKey,
    plaintext: &[u8],
) -> PyResult<(Capsule, PyObject)> {
    umbral_pre::encrypt(&delegating_pk.backend, plaintext)
        .map(|(backend_capsule, ciphertext)| {
            (backend_capsule.into(), PyBytes::new(py, &ciphertext).into())
        })
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

#[pyfunction]
pub fn decrypt_original(
    py: Python<'_>,
    delegating_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> PyResult<PyObject> {
    umbral_pre::decrypt_original(&delegating_sk.backend, &capsule.backend, ciphertext)
        .map(|plaintext| PyBytes::new(py, &plaintext).into())
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

#[pyclass(module = "umbral")]
#[derive(PartialEq, derive_more::AsRef, derive_more::From)]
pub struct KeyFrag {
    backend: umbral_pre::KeyFrag,
}

#[pymethods]
impl KeyFrag {
    pub fn verify(
        &self,
        verifying_pk: &PublicKey,
        delegating_pk: Option<&PublicKey>,
        receiving_pk: Option<&PublicKey>,
    ) -> PyResult<VerifiedKeyFrag> {
        self.backend
            .clone()
            .verify(
                &verifying_pk.backend,
                delegating_pk.map(|pk| &pk.backend),
                receiving_pk.map(|pk| &pk.backend),
            )
            .map_err(|(err, _kfrag)| VerificationError::new_err(format!("{}", err)))
            .map(VerifiedKeyFrag::from)
    }

    pub fn skip_verification(&self) -> VerifiedKeyFrag {
        VerifiedKeyFrag {
            backend: self.backend.clone().skip_verification(),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::KeyFrag>(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::KeyFrag::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(PartialEq, Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct VerifiedKeyFrag {
    backend: umbral_pre::VerifiedKeyFrag,
}

#[pymethods]
impl VerifiedKeyFrag {
    #[staticmethod]
    pub fn from_verified_bytes(data: &[u8]) -> PyResult<Self> {
        umbral_pre::VerifiedKeyFrag::from_verified_bytes(data)
            .map(Self::from)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::VerifiedKeyFrag::serialized_size()
    }

    pub fn unverify(&self) -> KeyFrag {
        KeyFrag {
            backend: self.backend.clone().unverify(),
        }
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
pub fn generate_kfrags(
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signer: &Signer,
    threshold: usize,
    shares: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<VerifiedKeyFrag> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &delegating_sk.backend,
        &receiving_pk.backend,
        &signer.backend,
        threshold,
        shares,
        sign_delegating_key,
        sign_receiving_key,
    );

    backend_kfrags
        .iter()
        .cloned()
        .map(|val| VerifiedKeyFrag { backend: val })
        .collect()
}

#[pyclass(module = "umbral")]
#[derive(Clone, PartialEq, derive_more::AsRef, derive_more::From)]
pub struct CapsuleFrag {
    backend: umbral_pre::CapsuleFrag,
}

#[pymethods]
impl CapsuleFrag {
    pub fn verify(
        &self,
        capsule: &Capsule,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> PyResult<VerifiedCapsuleFrag> {
        self.backend
            .clone()
            .verify(
                &capsule.backend,
                &verifying_pk.backend,
                &delegating_pk.backend,
                &receiving_pk.backend,
            )
            .map_err(|(err, _cfrag)| VerificationError::new_err(format!("{}", err)))
            .map(VerifiedCapsuleFrag::from)
    }

    pub fn skip_verification(&self) -> VerifiedCapsuleFrag {
        VerifiedCapsuleFrag {
            backend: self.backend.clone().skip_verification(),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::CapsuleFrag>(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::CapsuleFrag::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(PartialEq, Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct VerifiedCapsuleFrag {
    backend: umbral_pre::VerifiedCapsuleFrag,
}

#[pymethods]
impl VerifiedCapsuleFrag {
    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }

    #[staticmethod]
    pub fn from_verified_bytes(data: &[u8]) -> PyResult<Self> {
        umbral_pre::VerifiedCapsuleFrag::from_verified_bytes(data)
            .map(Self::from)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::VerifiedCapsuleFrag::serialized_size()
    }

    pub fn unverify(&self) -> CapsuleFrag {
        CapsuleFrag {
            backend: self.backend.clone().unverify(),
        }
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyfunction]
pub fn reencrypt(capsule: &Capsule, kfrag: &VerifiedKeyFrag) -> VerifiedCapsuleFrag {
    let backend_vcfrag = umbral_pre::reencrypt(&capsule.backend, kfrag.backend.clone());
    VerifiedCapsuleFrag::from(backend_vcfrag)
}

#[pyfunction]
pub fn decrypt_reencrypted(
    py: Python<'_>,
    receiving_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    verified_cfrags: Vec<VerifiedCapsuleFrag>,
    ciphertext: &[u8],
) -> PyResult<PyObject> {
    let backend_cfrags = verified_cfrags
        .iter()
        .cloned()
        .map(|vcfrag| vcfrag.backend)
        .collect::<Vec<_>>();
    umbral_pre::decrypt_reencrypted(
        &receiving_sk.backend,
        &delegating_pk.backend,
        &capsule.backend,
        backend_cfrags,
        ciphertext,
    )
    .map(|plaintext| PyBytes::new(py, &plaintext).into())
    .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

// Since adding functions in pyo3 requires a two-step process
// (`#[pyfunction]` + `wrap_pyfunction!`), and `wrap_pyfunction`
// needs `#[pyfunction]` in the same module, we need these trampolines
// to build modules externally.

pub fn register_encrypt(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)
}

pub fn register_decrypt_original(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decrypt_original, m)?)
}

pub fn register_generate_kfrags(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_kfrags, m)?)
}

pub fn register_reencrypt(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(reencrypt, m)?)
}

pub fn register_decrypt_reencrypted(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decrypt_reencrypted, m)?)
}
