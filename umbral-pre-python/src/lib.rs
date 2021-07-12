use pyo3::class::basic::CompareOp;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pyclass::PyClass;
use pyo3::types::{PyBytes, PyUnicode};
use pyo3::wrap_pyfunction;
use pyo3::PyObjectProtocol;

use umbral_pre::{
    DeserializableFromArray, HasTypeName, RepresentableAsArray, SerializableToArray,
    SerializableToSecretArray,
};

// Helper traits to generalize implementing various Python protocol functions for our types.

trait AsBackend<T> {
    fn as_backend(&self) -> &T;
}

trait FromBackend<T> {
    fn from_backend(backend: T) -> Self;
}

fn to_bytes<T, U>(obj: &T) -> PyResult<PyObject>
where
    T: AsBackend<U>,
    U: SerializableToArray,
{
    let serialized = obj.as_backend().to_array();
    Python::with_gil(|py| -> PyResult<PyObject> {
        Ok(PyBytes::new(py, serialized.as_slice()).into())
    })
}

// Can't keep the secret in Python anymore, so this function does the same as `to_bytes()`
fn to_secret_bytes<T, U>(obj: &T) -> PyResult<PyObject>
where
    T: AsBackend<U>,
    U: SerializableToSecretArray,
{
    // Dereferencing a secret.
    let serialized = obj.as_backend().to_secret_array().as_secret().clone();
    Python::with_gil(|py| -> PyResult<PyObject> {
        Ok(PyBytes::new(py, serialized.as_slice()).into())
    })
}

fn from_bytes<T, U>(data: &[u8]) -> PyResult<T>
where
    T: FromBackend<U>,
    U: DeserializableFromArray + HasTypeName,
{
    U::from_bytes(data)
        .map(T::from_backend)
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

fn hash<T, U>(obj: &T) -> PyResult<isize>
where
    T: AsBackend<U>,
    U: SerializableToArray + HasTypeName,
{
    let serialized = obj.as_backend().to_array();

    // call `hash((class_name, bytes(obj)))`
    Python::with_gil(|py| {
        let builtins = PyModule::import(py, "builtins")?;
        let arg1 = PyUnicode::new(py, U::type_name());
        let arg2: PyObject = PyBytes::new(py, serialized.as_slice()).into();
        builtins.getattr("hash")?.call1(((arg1, arg2),))?.extract()
    })
}

fn richcmp<T, U>(obj: &T, other: PyRef<T>, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq + AsBackend<U>,
    U: HasTypeName,
{
    match op {
        CompareOp::Eq => Ok(obj == &*other),
        CompareOp::Ne => Ok(obj != &*other),
        _ => Err(PyTypeError::new_err(format!(
            "{} objects are not ordered",
            U::type_name()
        ))),
    }
}

create_exception!(umbral, VerificationError, PyException);

#[pyclass(module = "umbral")]
pub struct SecretKey {
    backend: umbral_pre::SecretKey,
}

impl AsBackend<umbral_pre::SecretKey> for SecretKey {
    fn as_backend(&self) -> &umbral_pre::SecretKey {
        &self.backend
    }
}

impl FromBackend<umbral_pre::SecretKey> for SecretKey {
    fn from_backend(backend: umbral_pre::SecretKey) -> Self {
        Self { backend }
    }
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
        from_bytes(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::SecretKey::serialized_size()
    }
}

#[pyproto]
impl PyObjectProtocol for SecretKey {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
pub struct SecretKeyFactory {
    backend: umbral_pre::SecretKeyFactory,
}

impl AsBackend<umbral_pre::SecretKeyFactory> for SecretKeyFactory {
    fn as_backend(&self) -> &umbral_pre::SecretKeyFactory {
        &self.backend
    }
}

impl FromBackend<umbral_pre::SecretKeyFactory> for SecretKeyFactory {
    fn from_backend(backend: umbral_pre::SecretKeyFactory) -> Self {
        Self { backend }
    }
}

#[pymethods]
impl SecretKeyFactory {
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            backend: umbral_pre::SecretKeyFactory::random(),
        }
    }

    pub fn secret_key_by_label(&self, label: &[u8]) -> PyResult<SecretKey> {
        self.backend
            .secret_key_by_label(label)
            .map(|backend_sk| SecretKey {
                backend: backend_sk,
            })
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    pub fn secret_key_factory_by_label(&self, label: &[u8]) -> Self {
        Self {
            backend: self.backend.secret_key_factory_by_label(label),
        }
    }

    pub fn to_secret_bytes(&self) -> PyResult<PyObject> {
        to_secret_bytes(self)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::SecretKeyFactory::serialized_size()
    }
}

#[pyproto]
impl PyObjectProtocol for SecretKeyFactory {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(PartialEq)]
pub struct PublicKey {
    backend: umbral_pre::PublicKey,
}

impl AsBackend<umbral_pre::PublicKey> for PublicKey {
    fn as_backend(&self) -> &umbral_pre::PublicKey {
        &self.backend
    }
}

impl FromBackend<umbral_pre::PublicKey> for PublicKey {
    fn from_backend(backend: umbral_pre::PublicKey) -> Self {
        Self { backend }
    }
}

#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::PublicKey::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyproto]
impl PyObjectProtocol for PublicKey {
    fn __richcmp__(&self, other: PyRef<PublicKey>, op: CompareOp) -> PyResult<bool> {
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
pub struct Signer {
    backend: umbral_pre::Signer,
}

impl AsBackend<umbral_pre::Signer> for Signer {
    fn as_backend(&self) -> &umbral_pre::Signer {
        &self.backend
    }
}

#[pymethods]
impl Signer {
    #[new]
    pub fn new(sk: &SecretKey) -> Self {
        Self {
            backend: umbral_pre::Signer::new(&sk.backend),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            backend: self.backend.sign(message),
        }
    }

    pub fn verifying_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.verifying_key(),
        }
    }
}

#[pyproto]
impl PyObjectProtocol for Signer {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "umbral")]
#[derive(PartialEq)]
pub struct Signature {
    backend: umbral_pre::Signature,
}

impl AsBackend<umbral_pre::Signature> for Signature {
    fn as_backend(&self) -> &umbral_pre::Signature {
        &self.backend
    }
}

impl FromBackend<umbral_pre::Signature> for Signature {
    fn from_backend(backend: umbral_pre::Signature) -> Self {
        Self { backend }
    }
}

#[pymethods]
impl Signature {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    pub fn verify(&self, verifying_key: &PublicKey, message: &[u8]) -> bool {
        self.backend.verify(&verifying_key.backend, message)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::Signature::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyproto]
impl PyObjectProtocol for Signature {
    fn __richcmp__(&self, other: PyRef<Signature>, op: CompareOp) -> PyResult<bool> {
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
#[derive(PartialEq)]
pub struct Capsule {
    backend: umbral_pre::Capsule,
}

impl AsBackend<umbral_pre::Capsule> for Capsule {
    fn as_backend(&self) -> &umbral_pre::Capsule {
        &self.backend
    }
}

impl FromBackend<umbral_pre::Capsule> for Capsule {
    fn from_backend(backend: umbral_pre::Capsule) -> Self {
        Self { backend }
    }
}

#[pymethods]
impl Capsule {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::Capsule::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyproto]
impl PyObjectProtocol for Capsule {
    fn __richcmp__(&self, other: PyRef<Capsule>, op: CompareOp) -> PyResult<bool> {
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
    py: Python,
    delegating_pk: &PublicKey,
    plaintext: &[u8],
) -> PyResult<(Capsule, PyObject)> {
    umbral_pre::encrypt(&delegating_pk.backend, plaintext)
        .map(|(backend_capsule, ciphertext)| {
            (
                Capsule {
                    backend: backend_capsule,
                },
                PyBytes::new(py, &ciphertext).into(),
            )
        })
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

#[pyfunction]
pub fn decrypt_original(
    py: Python,
    delegating_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> PyResult<PyObject> {
    umbral_pre::decrypt_original(&delegating_sk.backend, &capsule.backend, &ciphertext)
        .map(|plaintext| PyBytes::new(py, &plaintext).into())
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

#[pyclass(module = "umbral")]
#[derive(PartialEq)]
pub struct KeyFrag {
    backend: umbral_pre::KeyFrag,
}

impl AsBackend<umbral_pre::KeyFrag> for KeyFrag {
    fn as_backend(&self) -> &umbral_pre::KeyFrag {
        &self.backend
    }
}

impl FromBackend<umbral_pre::KeyFrag> for KeyFrag {
    fn from_backend(backend: umbral_pre::KeyFrag) -> Self {
        Self { backend }
    }
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
            .verify(
                &verifying_pk.backend,
                delegating_pk.map(|pk| &pk.backend),
                receiving_pk.map(|pk| &pk.backend),
            )
            .map_err(|err| VerificationError::new_err(format!("{}", err)))
            .map(|backend_vkfrag| VerifiedKeyFrag {
                backend: backend_vkfrag,
            })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::KeyFrag::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyproto]
impl PyObjectProtocol for KeyFrag {
    fn __richcmp__(&self, other: PyRef<KeyFrag>, op: CompareOp) -> PyResult<bool> {
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
#[derive(PartialEq, Clone)]
pub struct VerifiedKeyFrag {
    backend: umbral_pre::VerifiedKeyFrag,
}

impl AsBackend<umbral_pre::VerifiedKeyFrag> for VerifiedKeyFrag {
    fn as_backend(&self) -> &umbral_pre::VerifiedKeyFrag {
        &self.backend
    }
}

#[pymethods]
impl VerifiedKeyFrag {
    #[staticmethod]
    pub fn from_verified_bytes(data: &[u8]) -> PyResult<Self> {
        umbral_pre::VerifiedKeyFrag::from_verified_bytes(data)
            .map(|vkfrag| Self { backend: vkfrag })
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::VerifiedKeyFrag::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyproto]
impl PyObjectProtocol for VerifiedKeyFrag {
    fn __richcmp__(&self, other: PyRef<VerifiedKeyFrag>, op: CompareOp) -> PyResult<bool> {
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
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<VerifiedKeyFrag> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &delegating_sk.backend,
        &receiving_pk.backend,
        &signer.backend,
        threshold,
        num_kfrags,
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
#[derive(Clone, PartialEq)]
pub struct CapsuleFrag {
    backend: umbral_pre::CapsuleFrag,
}

impl AsBackend<umbral_pre::CapsuleFrag> for CapsuleFrag {
    fn as_backend(&self) -> &umbral_pre::CapsuleFrag {
        &self.backend
    }
}

impl FromBackend<umbral_pre::CapsuleFrag> for CapsuleFrag {
    fn from_backend(backend: umbral_pre::CapsuleFrag) -> Self {
        Self { backend }
    }
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
            .verify(
                &capsule.backend,
                &verifying_pk.backend,
                &delegating_pk.backend,
                &receiving_pk.backend,
            )
            .map_err(|err| VerificationError::new_err(format!("{}", err)))
            .map(|backend_vcfrag| VerifiedCapsuleFrag {
                backend: backend_vcfrag,
            })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::CapsuleFrag::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyproto]
impl PyObjectProtocol for CapsuleFrag {
    fn __richcmp__(&self, other: PyRef<CapsuleFrag>, op: CompareOp) -> PyResult<bool> {
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
#[derive(PartialEq, Clone)]
pub struct VerifiedCapsuleFrag {
    backend: umbral_pre::VerifiedCapsuleFrag,
}

impl AsBackend<umbral_pre::VerifiedCapsuleFrag> for VerifiedCapsuleFrag {
    fn as_backend(&self) -> &umbral_pre::VerifiedCapsuleFrag {
        &self.backend
    }
}

#[pyproto]
impl PyObjectProtocol for VerifiedCapsuleFrag {
    fn __richcmp__(&self, other: PyRef<VerifiedCapsuleFrag>, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash(self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pymethods]
impl VerifiedCapsuleFrag {
    #[staticmethod]
    pub fn from_verified_bytes(data: &[u8]) -> PyResult<Self> {
        umbral_pre::VerifiedCapsuleFrag::from_verified_bytes(data)
            .map(|vcfrag| Self { backend: vcfrag })
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        umbral_pre::VerifiedCapsuleFrag::serialized_size()
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

#[pyfunction]
pub fn reencrypt(capsule: &Capsule, kfrag: &VerifiedKeyFrag) -> VerifiedCapsuleFrag {
    let backend_vcfrag = umbral_pre::reencrypt(&capsule.backend, &kfrag.backend);
    VerifiedCapsuleFrag {
        backend: backend_vcfrag,
    }
}

#[pyfunction]
pub fn decrypt_reencrypted(
    py: Python,
    receiving_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    verified_cfrags: Vec<VerifiedCapsuleFrag>,
    ciphertext: &[u8],
) -> PyResult<PyObject> {
    let backend_cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> = verified_cfrags
        .iter()
        .cloned()
        .map(|vcfrag| vcfrag.backend)
        .collect();
    umbral_pre::decrypt_reencrypted(
        &receiving_sk.backend,
        &delegating_pk.backend,
        &capsule.backend,
        &backend_cfrags,
        ciphertext,
    )
    .map(|plaintext| PyBytes::new(py, &plaintext).into())
    .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

/// A Python module implemented in Rust.
#[pymodule]
fn _umbral(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SecretKey>()?;
    m.add_class::<SecretKeyFactory>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<Signer>()?;
    m.add_class::<Signature>()?;
    m.add_class::<Capsule>()?;
    m.add_class::<KeyFrag>()?;
    m.add_class::<VerifiedKeyFrag>()?;
    m.add_class::<CapsuleFrag>()?;
    m.add_class::<VerifiedCapsuleFrag>()?;
    m.add("VerificationError", py.get_type::<VerificationError>())?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_original, m)?)?;
    m.add_function(wrap_pyfunction!(generate_kfrags, m)?)?;
    m.add_function(wrap_pyfunction!(reencrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_reencrypted, m)?)?;
    Ok(())
}
