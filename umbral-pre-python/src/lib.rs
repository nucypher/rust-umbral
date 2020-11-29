use generic_array::GenericArray;
use pyo3::prelude::*;
use umbral_pre as backend;
use umbral_pre::SerializableToArray;

#[pyclass(module = "umbral")]
pub struct SecretKey {
    #[allow(dead_code)]
    data: GenericArray<u8, <backend::SecretKey as SerializableToArray>::Size>,
}

#[pymethods]
impl SecretKey {
    /// Generates a secret key using the default RNG and returns it.
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            data: backend::SecretKey::random().to_array(),
        }
    }
}

impl SecretKey {
    #[allow(dead_code)]
    fn to_backend(&self) -> backend::SecretKey {
        backend::SecretKey::from_bytes(&self.data).unwrap()
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn umbral(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SecretKey>()?;
    Ok(())
}
