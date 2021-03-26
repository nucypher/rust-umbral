use alloc::boxed::Box;

use aead::{Aead, AeadInPlace, Payload};
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use generic_array::{ArrayLength, GenericArray};
use hkdf::Hkdf;
use rand_core::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use typenum::Unsigned;

/// Errors that can happen during symmetric encryption.
#[derive(Debug, PartialEq)]
pub enum EncryptionError {
    /// Given plaintext is too large for the backend to handle.
    PlaintextTooLarge,
}

/// Errors that can happend during symmetric decryption.
#[derive(Debug, PartialEq)]
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

pub(crate) fn kdf<T: ArrayLength<u8>>(
    seed: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> GenericArray<u8, T> {
    let hk = Hkdf::<Sha256>::new(salt, &seed);

    let mut okm = GenericArray::<u8, T>::default();

    let def_info = info.unwrap_or(&[]);

    // We can only get an error here if `T` is too large, and it's known at compile-time.
    hk.expand(&def_info, &mut okm).unwrap();

    okm
}

type NonceSize = <XChaCha20Poly1305 as AeadInPlace>::NonceSize;

pub(crate) struct DEM {
    cipher: XChaCha20Poly1305,
}

impl DEM {
    pub fn new(key_seed: &[u8]) -> Self {
        type KeySize = <XChaCha20Poly1305 as NewAead>::KeySize;
        let key_bytes = kdf::<KeySize>(&key_seed, None, None);
        let key = Key::from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new(key);
        Self { cipher }
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        authenticated_data: &[u8],
    ) -> Result<Box<[u8]>, EncryptionError> {
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        OsRng.fill_bytes(&mut nonce);
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

    use super::kdf;
    use crate::curve::CurvePoint;
    use crate::SerializableToArray;
    use typenum::U32;

    #[test]
    fn test_kdf() {
        let p1 = CurvePoint::generator();
        let salt = b"abcdefg";
        let info = b"sdasdasd";
        let key = kdf::<U32>(&p1.to_array(), Some(&salt[..]), Some(&info[..]));
        let key_same = kdf::<U32>(&p1.to_array(), Some(&salt[..]), Some(&info[..]));
        assert_eq!(key, key_same);

        let key_diff = kdf::<U32>(&p1.to_array(), None, Some(&info[..]));
        assert_ne!(key, key_diff);
    }
}
