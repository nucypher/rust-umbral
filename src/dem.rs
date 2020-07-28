use aead::{Aead, Payload};
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;
use rand_core::RngCore;

pub const DEM_KEYSIZE: usize = 32;
const DEM_NONCE_SIZE: usize = 12;

pub struct Ciphertext {
    nonce: Nonce,
    data: Vec<u8>,
}

pub struct UmbralDEM {
    cipher: ChaCha20Poly1305,
}

impl UmbralDEM {
    pub fn new(bytes: &[u8]) -> Self {
        let key = Key::from_slice(bytes);
        let cipher = ChaCha20Poly1305::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, data: &[u8], authenticated_data: &[u8]) -> Ciphertext {
        let mut nonce = [0u8; DEM_NONCE_SIZE];
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

    pub fn decrypt(&self, ciphertext: &Ciphertext, authenticated_data: &[u8]) -> Option<Vec<u8>> {
        let payload = Payload {
            msg: &ciphertext.data,
            aad: authenticated_data,
        };
        self.cipher.decrypt(&ciphertext.nonce, payload).ok()
    }
}
