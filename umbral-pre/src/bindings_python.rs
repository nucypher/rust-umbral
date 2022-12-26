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
use core::fmt;

use generic_array::{sequence::Split, typenum::U8, GenericArray};
use pyo3::class::basic::CompareOp;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pyclass::PyClass;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use sha2::{digest::Update, Digest, Sha256};

use crate as umbral_pre;
use crate::{curve::ScalarSize, DefaultDeserialize, DefaultSerialize, SecretBox};

fn map_py_value_err<T: fmt::Display>(err: T) -> PyErr {
    PyValueError::new_err(format!("{}", err))
}

fn to_bytes<T, U>(obj: &T) -> PyResult<PyObject>
where
    T: AsRef<U>,
    U: DefaultSerialize,
{
    let serialized = obj.as_ref().to_bytes().map_err(map_py_value_err)?;
    Python::with_gil(|py| -> PyResult<PyObject> { Ok(PyBytes::new(py, &serialized).into()) })
}

fn from_bytes<'de, T, U>(data: &'de [u8]) -> PyResult<T>
where
    T: From<U>,
    U: DefaultDeserialize<'de>,
{
    let backend = U::from_bytes(data).map_err(map_py_value_err)?;
    Ok(T::from(backend))
}

fn type_name<U>() -> &'static str {
    // TODO: for a slightly better user experience we can remove qualifiers here,
    // because the returned string will be something like "crate_name::module_name::TypeName"
    core::any::type_name::<U>()
}

fn hash(data: impl AsRef<[u8]>) -> i64 {
    // This function does not require a cryptographic hash,
    // we just need something fast that minimizes conflicts.
    let digest = Sha256::new().chain(data).finalize();
    let (chunk, _): (GenericArray<u8, U8>, _) = digest.split();
    let arr: [u8; 8] = chunk.try_into().unwrap();
    i64::from_be_bytes(arr)
}

fn richcmp<T, U>(obj: &T, other: &T, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq + AsRef<U>,
{
    match op {
        CompareOp::Eq => Ok(obj == other),
        CompareOp::Ne => Ok(obj != other),
        _ => Err(PyTypeError::new_err(format!(
            "{} objects are not ordered",
            type_name::<U>()
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

    pub fn to_be_bytes(&self) -> PyObject {
        let serialized = self.backend.to_be_bytes();
        Python::with_gil(|py| PyBytes::new(py, serialized.as_secret()).into())
    }

    #[staticmethod]
    pub fn from_be_bytes(data: &[u8]) -> PyResult<Self> {
        let arr = SecretBox::new(
            GenericArray::<u8, ScalarSize>::from_exact_iter(data.iter().cloned())
                .ok_or_else(|| map_py_value_err("Invalid length of a curve scalar"))?,
        );
        umbral_pre::SecretKey::try_from_be_bytes(&arr)
            .map_err(map_py_value_err)
            .map(Self::from)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.public_key(),
        }
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
            .map_err(map_py_value_err)
    }

    pub fn make_secret(&self, label: &[u8]) -> PyObject {
        let secret = self.backend.make_secret(label);
        let bytes: &[u8] = secret.as_secret().as_ref();
        Python::with_gil(|py| PyBytes::new(py, bytes).into())
    }

    pub fn make_key(&self, label: &[u8]) -> SecretKey {
        self.backend.make_key(label).into()
    }

    pub fn make_factory(&self, label: &[u8]) -> Self {
        self.backend.make_factory(label).into()
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
    fn from_compressed_bytes(data: &[u8]) -> PyResult<Self> {
        umbral_pre::PublicKey::try_from_compressed_bytes(data)
            .map_err(map_py_value_err)
            .map(Self::from)
    }

    fn to_compressed_bytes(&self) -> PyObject {
        let serialized = self.backend.to_compressed_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> i64 {
        hash(&self.backend.to_compressed_bytes())
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
    fn from_der_bytes(data: &[u8]) -> PyResult<Self> {
        umbral_pre::Signature::try_from_der_bytes(data)
            .map_err(map_py_value_err)
            .map(Self::from)
    }

    fn to_der_bytes(&self) -> PyObject {
        let serialized = self.backend.to_der_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }

    fn to_be_bytes(&self) -> PyObject {
        let serialized = self.backend.to_be_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }

    fn verify(&self, verifying_pk: &PublicKey, message: &[u8]) -> bool {
        self.backend.verify(&verifying_pk.backend, message)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> i64 {
        hash(&self.backend.to_der_bytes())
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

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn to_bytes_simple(&self) -> PyObject {
        let serialized = self.backend.to_bytes_simple();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<i64> {
        self.backend.to_bytes().map_err(map_py_value_err).map(hash)
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
        .map_err(map_py_value_err)
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
        .map_err(map_py_value_err)
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

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<i64> {
        self.backend.to_bytes().map_err(map_py_value_err).map(hash)
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

    fn __hash__(&self) -> PyResult<i64> {
        self.backend.to_bytes().map_err(map_py_value_err).map(hash)
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

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    fn to_bytes_simple(&self) -> PyObject {
        let serialized = self.backend.to_bytes_simple();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<i64> {
        self.backend.to_bytes().map_err(map_py_value_err).map(hash)
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

    fn __hash__(&self) -> PyResult<i64> {
        self.backend.to_bytes().map_err(map_py_value_err).map(hash)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
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
    .map_err(map_py_value_err)
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

#[pyclass(module = "umbral")]
#[derive(Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct CurvePoint {
    backend: umbral_pre::curve::CurvePoint,
}

#[pymethods]
impl CurvePoint {
    #[getter]
    fn coordinates(&self) -> Option<(PyObject, PyObject)> {
        let coords = self.backend.coordinates();
        Python::with_gil(|py| -> Option<(PyObject, PyObject)> {
            coords.map(|(x, y)| {
                (
                    PyBytes::new(py, x.as_ref()).into(),
                    PyBytes::new(py, y.as_ref()).into(),
                )
            })
        })
    }
}

#[pyclass(module = "umbral")]
#[derive(Clone, derive_more::AsRef, derive_more::From, derive_more::Into)]
pub struct ReencryptionEvidence {
    backend: umbral_pre::ReencryptionEvidence,
}

#[pymethods]
impl ReencryptionEvidence {
    #[new]
    pub fn new(
        capsule: &Capsule,
        vcfrag: &VerifiedCapsuleFrag,
        verifying_pk: &PublicKey,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
    ) -> Self {
        umbral_pre::ReencryptionEvidence::new(
            &capsule.backend.clone(),
            &vcfrag.backend.clone(),
            &verifying_pk.backend.clone(),
            &delegating_pk.backend.clone(),
            &receiving_pk.backend.clone(),
        )
        .into()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, umbral_pre::ReencryptionEvidence>(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    #[getter]
    fn e(&self) -> CurvePoint {
        self.backend.e.into()
    }
    #[getter]
    fn ez(&self) -> CurvePoint {
        self.backend.ez.into()
    }
    #[getter]
    fn e1(&self) -> CurvePoint {
        self.backend.e1.into()
    }
    #[getter]
    fn e1h(&self) -> CurvePoint {
        self.backend.e1h.into()
    }
    #[getter]
    fn e2(&self) -> CurvePoint {
        self.backend.e2.into()
    }

    #[getter]
    fn v(&self) -> CurvePoint {
        self.backend.v.into()
    }
    #[getter]
    fn vz(&self) -> CurvePoint {
        self.backend.vz.into()
    }
    #[getter]
    fn v1(&self) -> CurvePoint {
        self.backend.v1.into()
    }
    #[getter]
    fn v1h(&self) -> CurvePoint {
        self.backend.v1h.into()
    }
    #[getter]
    fn v2(&self) -> CurvePoint {
        self.backend.v2.into()
    }

    #[getter]
    fn uz(&self) -> CurvePoint {
        self.backend.uz.into()
    }
    #[getter]
    fn u1(&self) -> CurvePoint {
        self.backend.u1.into()
    }
    #[getter]
    fn u1h(&self) -> CurvePoint {
        self.backend.u1h.into()
    }
    #[getter]
    fn u2(&self) -> CurvePoint {
        self.backend.u2.into()
    }

    #[getter]
    fn precursor(&self) -> CurvePoint {
        self.backend.precursor.into()
    }

    #[getter]
    fn kfrag_validity_message_hash(&self) -> PyObject {
        Python::with_gil(|py| -> PyObject {
            PyBytes::new(py, self.backend.kfrag_validity_message_hash.as_ref()).into()
        })
    }

    #[getter]
    fn kfrag_signature_v(&self) -> bool {
        self.backend.kfrag_signature_v
    }
}
