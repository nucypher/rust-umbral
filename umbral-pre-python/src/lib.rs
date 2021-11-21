use pyo3::prelude::*;

use umbral_pre;

/// A Python module implemented in Rust.
#[pymodule]
fn _umbral(py: Python, m: &PyModule) -> PyResult<()> {
    umbral_pre::bindings_python::build_module(py, m)?;
    Ok(())
}
