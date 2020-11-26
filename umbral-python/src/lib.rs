use generic_array::GenericArray;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use umbral as backend;
use umbral::SerializableToArray;

#[pyclass(module = "umbral")]
pub struct UmbralSecretKey {
    data: GenericArray<u8, <backend::UmbralSecretKey as SerializableToArray>::Size>,
}

#[pymethods]
impl UmbralSecretKey {
    /// Generates a secret key using the default RNG and returns it.
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            data: backend::UmbralSecretKey::random().to_array(),
        }
    }
}

impl UmbralSecretKey {
    fn to_backend(&self) -> backend::UmbralSecretKey {
        backend::UmbralSecretKey::from_bytes(&self.data).unwrap()
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn umbral(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<UmbralSecretKey>()?;
    Ok(())
}
