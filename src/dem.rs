#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use aead::{Aead, Payload};

use aead::{AeadInPlace, Buffer};
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use generic_array::{typenum::Unsigned, GenericArray};
use rand_core::OsRng;
use rand_core::RngCore;

// TODO: put everything in a single vector, same as the heapless version?
#[cfg(feature = "std")]
pub struct Ciphertext {
    nonce: Nonce,
    data: Vec<u8>,
}

pub struct UmbralDEM {
    cipher: ChaCha20Poly1305,
}

pub struct DemError();

impl UmbralDEM {
    pub fn new(bytes: &[u8]) -> Self {
        let key = Key::from_slice(bytes);
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
    ) -> Result<(), DemError> {
        type NonceSize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize;
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);
        let result = self
            .cipher
            .encrypt_in_place(&nonce, authenticated_data, buffer);
        match result {
            Ok(_) => {
                let res2 = buffer.extend_from_slice(&nonce);
                match res2 {
                    Ok(_) => Ok(()),
                    Err(_) => Err(DemError()),
                }
            }
            Err(_) => Err(DemError()),
        }
    }

    pub fn decrypt_in_place(
        &self,
        buffer: &mut dyn Buffer,
        authenticated_data: &[u8],
    ) -> Result<(), DemError> {
        let nonce_size = <<ChaCha20Poly1305 as AeadInPlace>::NonceSize as Unsigned>::to_usize();
        let buf_size = buffer.len();

        let nonce = Nonce::clone_from_slice(&buffer.as_ref()[buf_size - nonce_size..buf_size]);
        buffer.truncate(buf_size - nonce_size);
        let result = self
            .cipher
            .decrypt_in_place(&nonce, authenticated_data, buffer);
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(DemError()),
        }
    }

    #[cfg(feature = "std")]
    pub fn encrypt(&self, data: &[u8], authenticated_data: &[u8]) -> Ciphertext {
        type NonceSize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize;
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);
        let payload = Payload {
            msg: data,
            aad: authenticated_data,
        };
        let enc_data = self.cipher.encrypt(nonce, payload);
        // Ciphertext will be a 12 byte nonce, the ciphertext, and a 16 byte tag.

        Ciphertext {
            nonce: *nonce,
            data: enc_data.unwrap(),
        }
    }

    #[cfg(feature = "std")]
    pub fn decrypt(&self, ciphertext: &Ciphertext, authenticated_data: &[u8]) -> Option<Vec<u8>> {
        let payload = Payload {
            msg: &ciphertext.data,
            aad: authenticated_data,
        };
        self.cipher.decrypt(&ciphertext.nonce, payload).ok()
    }
}
