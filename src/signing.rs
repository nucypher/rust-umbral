use crate::params::UmbralParameters;
use crate::curve::CurveScalar;
use crate::keys::{UmbralPrivateKey, EllipticCurvePrivateKey};

/*
Wrapper for ECDSA signatures.
We store signatures as r and s; this class allows interoperation
between (r, s) and DER formatting.
*/
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    r: CurveScalar,
    s: CurveScalar,
}


impl Signature {

    fn new() -> Self {
        Self { r: CurveScalar::default(), s: CurveScalar::default() }
    }
}



/// Callable wrapping ECDSA signing with UmbralPrivateKeys
pub struct Signer {
    private_key: EllipticCurvePrivateKey,
    params: UmbralParameters,
}

impl Signer {

    // TODO: original allowed to select the hash algorithm, but it wasn't actually used anywhere
    // We're using the default, sha256
    pub fn new(umbral_private_key: &UmbralPrivateKey) -> Self {
        let private_key = umbral_private_key.to_cryptography_privkey();
        Self { private_key, params: umbral_private_key.params }
    }

    // Former __call__(); can't do that in Rust
    // Signs the message with this instance's private key.
    fn sign_prehashed(&self, digest: &[u8]) -> Signature {
        // TODO: `private_key` should implement `DigestSigner` trait.
        //let signature = self.private_key.sign_digest(digest);
        //Signature::from_bytes(signature.to_bytes());
        Signature::new()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        // TODO: `private_key` should implement `Signer` trait.
        //let signature = self.private_key.sign(message);
        //Signature::from_bytes(signature.to_bytes());
        Signature::new()
    }
}
