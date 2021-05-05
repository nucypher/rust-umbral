use pyo3::class::basic::CompareOp;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::PyObjectProtocol;

use umbral_pre::SerializableToArray;

#[pyclass(module = "umbral")]
#[derive(PartialEq)]
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

    pub fn __bytes__(&self, py: Python) -> PyObject {
        let serialized = self.backend.to_array();
        PyBytes::new(py, serialized.as_slice()).into()
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let backend_key = umbral_pre::SecretKey::from_bytes(bytes)?;
        Some(Self {
            backend: backend_key,
        })
    }
}

#[pyproto]
impl PyObjectProtocol for SecretKey {
    fn __richcmp__(&self, other: PyRef<SecretKey>, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self == &*other),
            CompareOp::Ne => Ok(self != &*other),
            _ => Err(PyTypeError::new_err("SecretKey objects are not ordered")),
        }
    }
}

#[pyclass(module = "umbral")]
pub struct SecretKeyFactory {
    backend: umbral_pre::SecretKeyFactory,
}

#[pymethods]
impl SecretKeyFactory {
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            backend: umbral_pre::SecretKeyFactory::random(),
        }
    }

    pub fn secret_key_by_label(&self, label: &[u8]) -> Option<SecretKey> {
        let backend_sk = self.backend.secret_key_by_label(label)?;
        Some(SecretKey {
            backend: backend_sk,
        })
    }

    pub fn __bytes__(&self, py: Python) -> PyObject {
        let serialized = self.backend.to_array();
        PyBytes::new(py, serialized.as_slice()).into()
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let backend_factory = umbral_pre::SecretKeyFactory::from_bytes(bytes)?;
        Some(Self {
            backend: backend_factory,
        })
    }
}

#[pyclass(module = "umbral")]
#[derive(PartialEq)]
pub struct PublicKey {
    backend: umbral_pre::PublicKey,
}

#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn from_secret_key(sk: &SecretKey) -> Self {
        Self {
            backend: umbral_pre::PublicKey::from_secret_key(&sk.backend),
        }
    }

    pub fn __bytes__(&self, py: Python) -> PyObject {
        let serialized = self.backend.to_array();
        PyBytes::new(py, serialized.as_slice()).into()
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let backend_pubkey = umbral_pre::PublicKey::from_bytes(bytes)?;
        Some(Self {
            backend: backend_pubkey,
        })
    }
}

#[pyproto]
impl PyObjectProtocol for PublicKey {
    fn __richcmp__(&self, other: PyRef<PublicKey>, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self == &*other),
            CompareOp::Ne => Ok(self != &*other),
            _ => Err(PyTypeError::new_err("PublicKey objects are not ordered")),
        }
    }
}

#[pyclass(module = "umbral")]
pub struct Capsule {
    backend: umbral_pre::Capsule,
}

#[pymethods]
impl Capsule {
    pub fn __bytes__(&self, py: Python) -> PyObject {
        let serialized = self.backend.to_array();
        PyBytes::new(py, serialized.as_slice()).into()
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let backend_capsule = umbral_pre::Capsule::from_bytes(bytes)?;
        Some(Self {
            backend: backend_capsule,
        })
    }
}

#[pyfunction]
pub fn encrypt(py: Python, pk: &PublicKey, plaintext: &[u8]) -> (Capsule, PyObject) {
    let (capsule, ciphertext) = umbral_pre::encrypt(&pk.backend, plaintext).unwrap();
    (
        Capsule { backend: capsule },
        PyBytes::new(py, &ciphertext).into(),
    )
}

#[pyfunction]
pub fn decrypt_original(
    py: Python,
    sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> PyObject {
    let plaintext =
        umbral_pre::decrypt_original(&sk.backend, &capsule.backend, &ciphertext).unwrap();
    PyBytes::new(py, &plaintext).into()
}

#[pyclass(module = "umbral")]
pub struct KeyFrag {
    backend: umbral_pre::KeyFrag,
}

#[pymethods]
impl KeyFrag {
    pub fn verify(
        &self,
        signing_pk: &PublicKey,
        delegating_pk: Option<&PublicKey>,
        receiving_pk: Option<&PublicKey>,
    ) -> bool {
        self.backend.verify(
            &signing_pk.backend,
            delegating_pk.map(|pk| &pk.backend),
            receiving_pk.map(|pk| &pk.backend),
        )
    }

    pub fn __bytes__(&self, py: Python) -> PyObject {
        let serialized = self.backend.to_array();
        PyBytes::new(py, serialized.as_slice()).into()
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let backend_kfrag = umbral_pre::KeyFrag::from_bytes(bytes)?;
        Some(Self {
            backend: backend_kfrag,
        })
    }
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
pub fn generate_kfrags(
    delegating_sk: &SecretKey,
    receiving_pk: &PublicKey,
    signing_sk: &SecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<KeyFrag> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &delegating_sk.backend,
        &receiving_pk.backend,
        &signing_sk.backend,
        threshold,
        num_kfrags,
        sign_delegating_key,
        sign_receiving_key,
    );

    backend_kfrags
        .iter()
        .cloned()
        .map(|val| KeyFrag { backend: val })
        .collect()
}

#[pyclass(module = "umbral")]
#[derive(Clone)]
pub struct CapsuleFrag {
    backend: umbral_pre::CapsuleFrag,
}

#[pymethods]
impl CapsuleFrag {
    pub fn verify(
        &self,
        capsule: &Capsule,
        delegating_pk: &PublicKey,
        receiving_pk: &PublicKey,
        signing_pk: &PublicKey,
        metadata: Option<&[u8]>,
    ) -> bool {
        self.backend.verify(
            &capsule.backend,
            &delegating_pk.backend,
            &receiving_pk.backend,
            &signing_pk.backend,
            metadata,
        )
    }

    pub fn __bytes__(&self, py: Python) -> PyObject {
        let serialized = self.backend.to_array();
        PyBytes::new(py, serialized.as_slice()).into()
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let backend_cfrag = umbral_pre::CapsuleFrag::from_bytes(bytes)?;
        Some(Self {
            backend: backend_cfrag,
        })
    }
}

#[pyfunction]
pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag, metadata: Option<&[u8]>) -> CapsuleFrag {
    let backend_cfrag = umbral_pre::reencrypt(&capsule.backend, &kfrag.backend, metadata);
    CapsuleFrag {
        backend: backend_cfrag,
    }
}

#[pyfunction]
pub fn decrypt_reencrypted(
    py: Python,
    decrypting_sk: &SecretKey,
    delegating_pk: &PublicKey,
    capsule: &Capsule,
    cfrags: Vec<CapsuleFrag>,
    ciphertext: &[u8],
) -> Option<PyObject> {
    let backend_cfrags: Vec<umbral_pre::CapsuleFrag> =
        cfrags.iter().cloned().map(|cfrag| cfrag.backend).collect();
    let res = umbral_pre::decrypt_reencrypted(
        &decrypting_sk.backend,
        &delegating_pk.backend,
        &capsule.backend,
        &backend_cfrags,
        ciphertext,
    );
    match res {
        Some(plaintext) => Some(PyBytes::new(py, &plaintext).into()),
        None => None,
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _umbral(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SecretKey>()?;
    m.add_class::<SecretKeyFactory>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<Capsule>()?;
    m.add_class::<KeyFrag>()?;
    m.add_class::<CapsuleFrag>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_original, m)?)?;
    m.add_function(wrap_pyfunction!(generate_kfrags, m)?)?;
    m.add_function(wrap_pyfunction!(reencrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_reencrypted, m)?)?;
    Ok(())
}
