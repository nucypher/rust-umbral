use pyo3::prelude::*;

use umbral_pre::bindings_python::*;

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
    m.add_class::<ReencryptionEvidence>()?;
    m.add_class::<CurvePoint>()?;
    m.add("VerificationError", py.get_type::<VerificationError>())?;
    register_encrypt(m)?;
    register_decrypt_original(m)?;
    register_generate_kfrags(m)?;
    register_reencrypt(m)?;
    register_decrypt_reencrypted(m)?;
    Ok(())
}
