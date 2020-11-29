use alloc::boxed::Box;

use aead::{Aead, AeadInPlace, Payload};
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

    pub fn encrypt(&self, data: &[u8], authenticated_data: &[u8]) -> Option<Box<[u8]>> {
        type NonceSize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize;
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);
        let payload = Payload {
            msg: data,
            aad: authenticated_data,
        };

        let mut result = nonce.to_vec();
        let enc_data = self.cipher.encrypt(nonce, payload).ok()?;
        // Somewhat inefficient, but it doesn't seem that you can pass
        // a mutable view of a vector to encrypt_in_place().
        result.extend(enc_data);
        Some(result.into_boxed_slice())
    }

    pub fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        authenticated_data: &[u8],
    ) -> Option<Box<[u8]>> {
        let nonce_size = <<ChaCha20Poly1305 as AeadInPlace>::NonceSize as Unsigned>::to_usize();
        let buf_size = ciphertext.as_ref().len();

        if buf_size < nonce_size {
            return None;
        }

        let nonce = Nonce::from_slice(&ciphertext.as_ref()[..nonce_size]);
        let payload = Payload {
            msg: &ciphertext.as_ref()[nonce_size..],
            aad: authenticated_data,
        };
        self.cipher
            .decrypt(&nonce, payload)
            .ok()
            .map(|pt| pt.into_boxed_slice())
    }
}

#[cfg(test)]
mod tests {

    use super::kdf;
    use crate::curve::CurvePoint;
    use crate::SerializableToArray;

    #[test]
    fn test_kdf() {
        let p1 = CurvePoint::generator();
        let salt = b"abcdefg";
        let info = b"sdasdasd";
        let key = kdf(&p1.to_array(), Some(&salt[..]), Some(&info[..]));
        let key_same = kdf(&p1.to_array(), Some(&salt[..]), Some(&info[..]));
        assert_eq!(key, key_same);

        let key_diff = kdf(&p1.to_array(), None, Some(&info[..]));
        assert_ne!(key, key_diff);
    }
}
