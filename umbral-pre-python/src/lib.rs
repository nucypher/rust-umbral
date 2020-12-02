use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

#[pyclass(module = "umbral")]
pub struct SecretKey {
    backend: umbral_pre::SecretKey,
}

#[pymethods]
impl SecretKey {
    /// Generates a secret key using the default RNG and returns it.
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            backend: umbral_pre::SecretKey::random(),
        }
    }
}

#[pyclass(module = "umbral")]
pub struct PublicKey {
    backend: umbral_pre::PublicKey,
}

#[pymethods]
impl PublicKey {
    /// Generates a secret key using the default RNG and returns it.
    #[staticmethod]
    pub fn from_secret_key(sk: &SecretKey) -> Self {
        Self {
            backend: umbral_pre::PublicKey::from_secret_key(&sk.backend),
        }
    }
}

#[pyclass(module = "umbral")]
pub struct Parameters {
    backend: umbral_pre::Parameters,
}

#[pymethods]
impl Parameters {
    #[new]
    pub fn new() -> Self {
        Self {
            backend: umbral_pre::Parameters::new(),
        }
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::new()
    }
}

#[pyclass(module = "umbral")]
#[derive(Clone)]
pub struct Capsule {
    backend: umbral_pre::Capsule,
}

#[pyfunction]
pub fn encrypt(
    py: Python,
    params: &Parameters,
    pk: &PublicKey,
    plaintext: &[u8],
) -> (Capsule, PyObject) {
    let (capsule, ciphertext) =
        umbral_pre::encrypt(&params.backend, &pk.backend, plaintext).unwrap();
    (
        Capsule { backend: capsule },
        PyBytes::new(py, &ciphertext).into(),
    )
}

#[pyfunction]
pub fn decrypt_original(
    py: Python,
    decrypting_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: &[u8],
) -> PyObject {
    let plaintext =
        umbral_pre::decrypt_original(&decrypting_sk.backend, &capsule.backend, &ciphertext)
            .unwrap();
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
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
pub fn generate_kfrags(
    params: &Parameters,
    delegating_sk: &SecretKey,
    receiving_pubkey: &PublicKey,
    signing_sk: &SecretKey,
    threshold: usize,
    num_kfrags: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
) -> Vec<KeyFrag> {
    let backend_kfrags = umbral_pre::generate_kfrags(
        &params.backend,
        &delegating_sk.backend,
        &receiving_pubkey.backend,
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
        signing_pubkey: &PublicKey,
        delegating_pubkey: &PublicKey,
        receiving_pubkey: &PublicKey,
    ) -> bool {
        self.backend.verify(
            &capsule.backend,
            &signing_pubkey.backend,
            &delegating_pubkey.backend,
            &receiving_pubkey.backend,
        )
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
fn umbral(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SecretKey>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<Parameters>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?).unwrap();
    m.add_function(wrap_pyfunction!(decrypt_original, m)?)
        .unwrap();
    m.add_function(wrap_pyfunction!(generate_kfrags, m)?)
        .unwrap();
    m.add_function(wrap_pyfunction!(reencrypt, m)?).unwrap();
    m.add_function(wrap_pyfunction!(decrypt_reencrypted, m)?)
        .unwrap();
    Ok(())
}
