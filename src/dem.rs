#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use aead::{Aead, Payload};

use aead::{AeadInPlace, Buffer};
use blake2::Blake2b;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use generic_array::{typenum::Unsigned, GenericArray};
use hkdf::Hkdf;
use rand_core::OsRng;
use rand_core::RngCore;

type KdfSize = <ChaCha20Poly1305 as NewAead>::KeySize;

fn kdf(seed: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>) -> GenericArray<u8, KdfSize> {
    let hk = Hkdf::<Blake2b>::new(salt, &seed);

    let mut okm = GenericArray::<u8, KdfSize>::default();

    let def_info = match info {
        Some(x) => x,
        None => &[],
    };

    // We can only get an error here if `KdfSize` is too large, and it's known at compile-time.
    hk.expand(&def_info, &mut okm).unwrap();

    okm
}

pub(crate) struct UmbralDEM {
    cipher: ChaCha20Poly1305,
}

impl UmbralDEM {
    pub fn new(key_seed: &[u8]) -> Self {
        let key_bytes = kdf(&key_seed, None, None);
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        Self { cipher }
    }

    // TODO: use in a test somewhere
    /*
    pub fn ciphertext_size_for(plaintext_size: usize) -> usize {
        let overhead =
            <<ChaCha20Poly1305 as AeadInPlace>::CiphertextOverhead as Unsigned>::to_usize();
        let tag_size = <<ChaCha20Poly1305 as AeadInPlace>::TagSize as Unsigned>::to_usize();
        let nonce_size = <<ChaCha20Poly1305 as AeadInPlace>::NonceSize as Unsigned>::to_usize();
        plaintext_size + tag_size + overhead + nonce_size
    }
    */

    pub fn encrypt_in_place(
        &self,
        buffer: &mut dyn Buffer,
        authenticated_data: &[u8],
    ) -> Option<()> {
        type NonceSize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize;
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);
        let result = self
            .cipher
            .encrypt_in_place(&nonce, authenticated_data, buffer);
        match result {
            // It would be better to add the nonce in front,
            // but `Buffer` can only be extended from the end.
            Ok(_) => {
                let res2 = buffer.extend_from_slice(&nonce);
                match res2 {
                    Ok(_) => Some(()),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }

    pub fn decrypt_in_place(
        &self,
        buffer: &mut dyn Buffer,
        authenticated_data: &[u8],
    ) -> Option<()> {
        let nonce_size = <<ChaCha20Poly1305 as AeadInPlace>::NonceSize as Unsigned>::to_usize();
        let buf_size = buffer.len();

        if buf_size < nonce_size {
            return None;
        }

        let nonce = Nonce::clone_from_slice(&buffer.as_ref()[buf_size - nonce_size..buf_size]);
        buffer.truncate(buf_size - nonce_size);
        let result = self
            .cipher
            .decrypt_in_place(&nonce, authenticated_data, buffer);
        match result {
            Ok(_) => Some(()),
            Err(_) => None,
        }
    }

    #[cfg(feature = "std")]
    pub fn encrypt(&self, data: &[u8], authenticated_data: &[u8]) -> Vec<u8> {
        type NonceSize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize;
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);
        let payload = Payload {
            msg: data,
            aad: authenticated_data,
        };
        let mut enc_data = self.cipher.encrypt(nonce, payload).unwrap();

        // Add nonce at the end to keep the compatibility with `encrypt_in_place()`
        // (see the note there)
        enc_data.extend_from_slice(&nonce);

        enc_data
    }

    #[cfg(feature = "std")]
    pub fn decrypt(&self, ciphertext: &Vec<u8>, authenticated_data: &[u8]) -> Option<Vec<u8>> {
        let nonce_size = <<ChaCha20Poly1305 as AeadInPlace>::NonceSize as Unsigned>::to_usize();
        let buf_size = ciphertext.len();

        if buf_size < nonce_size {
            return None;
        }

        let nonce = Nonce::from_slice(&ciphertext[buf_size - nonce_size..buf_size]);
        let payload = Payload {
            msg: &ciphertext[0..buf_size - nonce_size],
            aad: authenticated_data,
        };
        self.cipher.decrypt(&nonce, payload).ok()
    }
}

#[cfg(test)]
mod tests {

    use super::kdf;
    use crate::curve::{point_to_hash_seed, CurvePoint};

    #[test]
    fn test_kdf() {
        let p1 = CurvePoint::generator();
        let salt = b"abcdefg";
        let info = b"sdasdasd";
        let key = kdf(&point_to_hash_seed(&p1), Some(&salt[..]), Some(&info[..]));
        let key_same = kdf(&point_to_hash_seed(&p1), Some(&salt[..]), Some(&info[..]));
        assert_eq!(key, key_same);

        let key_diff = kdf(&point_to_hash_seed(&p1), None, Some(&info[..]));
        assert_ne!(key, key_diff);
    }
}
