use alloc::boxed::Box;
use core::fmt;

use aead::{Aead, AeadCore, Payload};
use chacha20poly1305::{Key, KeyInit, KeySizeUser, XChaCha20Poly1305, XNonce};
use generic_array::{ArrayLength, GenericArray};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use typenum::Unsigned;
use zeroize::ZeroizeOnDrop;

use crate::secret_box::SecretBox;

/// Errors that can happen during symmetric encryption.
#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionError {
    /// Given plaintext is too large for the backend to handle.
    PlaintextTooLarge,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextTooLarge => write!(f, "Plaintext is too large to encrypt"),
        }
    }
}

/// Errors that can happend during symmetric decryption.
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptionError {
    /// Ciphertext (which should be prepended by the nonce) is shorter than the nonce length.
    CiphertextTooShort,
    /// The ciphertext and the attached authentication data are inconsistent.
    /// This can happen if:
    /// - an incorrect key is used,
    /// - the ciphertext is modified or cut short,
    /// - an incorrect authentication data is provided on decryption.
    AuthenticationFailed,
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextTooShort => write!(f, "The ciphertext must include the nonce"),
            Self::AuthenticationFailed => write!(
                f,
                "Decryption of ciphertext failed: \
                either someone tampered with the ciphertext or \
                you are using an incorrect decryption key."
            ),
        }
    }
}

pub(crate) fn kdf<S: ArrayLength<u8>>(
    seed: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> SecretBox<GenericArray<u8, S>> {
    let hk = Hkdf::<Sha256>::new(salt, seed);

    let mut okm = SecretBox::new(GenericArray::<u8, S>::default());

    let def_info = info.unwrap_or(&[]);

    // We can only get an error here if `S` is too large, and it's known at compile-time.
    hk.expand(def_info, okm.as_mut_secret()).unwrap();

    okm
}

type NonceSize = <XChaCha20Poly1305 as AeadCore>::NonceSize;

#[allow(clippy::upper_case_acronyms)]
#[derive(ZeroizeOnDrop)]
pub(crate) struct DEM {
    cipher: XChaCha20Poly1305,
}

impl DEM {
    pub fn new(key_seed: &[u8]) -> Self {
        type KeySize = <XChaCha20Poly1305 as KeySizeUser>::KeySize;
        let key_bytes = kdf::<KeySize>(key_seed, None, None);
        // Note that unlike `XChaCha20Poly1305`, `Key` is *not* zeroized automatically,
        // so we are wrapping it into a secret box.
        let key = SecretBox::new(*Key::from_slice(key_bytes.as_secret()));
        let cipher = XChaCha20Poly1305::new(key.as_secret());
        Self { cipher }
    }

    pub fn encrypt(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        data: &[u8],
        authenticated_data: &[u8],
    ) -> Result<Box<[u8]>, EncryptionError> {
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        rng.fill_bytes(&mut nonce);
        let nonce = XNonce::from_slice(&nonce);
        let payload = Payload {
            msg: data,
            aad: authenticated_data,
        };

        let mut result = nonce.to_vec();
        let enc_data = self
            .cipher
            .encrypt(nonce, payload)
            .or(Err(EncryptionError::PlaintextTooLarge))?;

        // Somewhat inefficient, but it doesn't seem that you can pass
        // a mutable view of a vector to encrypt_in_place().
        result.extend(enc_data);
        Ok(result.into_boxed_slice())
    }

    pub fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        authenticated_data: &[u8],
    ) -> Result<Box<[u8]>, DecryptionError> {
        let nonce_size = <NonceSize as Unsigned>::to_usize();
        let buf_size = ciphertext.as_ref().len();

        if buf_size < nonce_size {
            return Err(DecryptionError::CiphertextTooShort);
        }

        let nonce = XNonce::from_slice(&ciphertext.as_ref()[..nonce_size]);
        let payload = Payload {
            msg: &ciphertext.as_ref()[nonce_size..],
            aad: authenticated_data,
        };
        self.cipher
            .decrypt(nonce, payload)
            .map(|pt| pt.into_boxed_slice())
            .or(Err(DecryptionError::AuthenticationFailed))
    }
}

#[cfg(test)]
mod tests {

    use typenum::U32;

    use super::kdf;
    use crate::curve::CurvePoint;
    use crate::secret_box::SecretBox;
    use crate::SerializableToArray;

    #[test]
    fn test_kdf() {
        let p1 = CurvePoint::generator();
        let salt = b"abcdefg";
        let info = b"sdasdasd";
        let seed = SecretBox::new(p1.to_array());
        let key = kdf::<U32>(seed.as_secret(), Some(&salt[..]), Some(&info[..]));
        let key_same = kdf::<U32>(seed.as_secret(), Some(&salt[..]), Some(&info[..]));
        assert_eq!(key.as_secret(), key_same.as_secret());

        let key_diff = kdf::<U32>(seed.as_secret(), None, Some(&info[..]));
        assert_ne!(key.as_secret(), key_diff.as_secret());
    }
}
