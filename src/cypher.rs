use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};

use crate::{Payload, RawPayload, Shellcode};

pub trait PayloadCypher: Payload {
    type Key;
    type InnerPayload: Payload;
    fn decrypt(self, key: &Self::Key) -> Self::InnerPayload;
}
impl<T: PayloadCypher> Payload for T {}

pub struct XorCypher<T: Payload = Shellcode> {
    inner: RawPayload,
    _marker: std::marker::PhantomData<T>,
}

impl<P: Payload> From<RawPayload> for XorCypher<P> {
    fn from(inner: RawPayload) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, P: Payload> PayloadCypher for XorCypher<P> {
    type Key = u8;
    type InnerPayload = P;

    fn decrypt(self, key: &Self::Key) -> P {
        let vec = self.inner.to_vec();
        vec.into_iter().map(|x| x ^ key).collect::<Vec<u8>>().into()
    }
}

pub trait XorCypherExt {
    fn xor_encrypt(self, key: &u8) -> RawPayload;
}

impl XorCypherExt for RawPayload {
    fn xor_encrypt(self, key: &u8) -> RawPayload {
        let mut inner = self.to_vec();
        for byte in inner.iter_mut() {
            *byte ^= key;
        }
        inner
    }
}

#[cfg(feature = "aes")]
pub struct AesCypher<T: Payload = Shellcode> {
    inner: RawPayload,
    _marker: std::marker::PhantomData<T>,
}

#[cfg(feature = "aes")]
impl<P: Payload> From<RawPayload> for AesCypher<P> {
    fn from(inner: RawPayload) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "aes")]
impl<'a, P: Payload> PayloadCypher for AesCypher<P> {
    type Key = [u8; 32];
    type InnerPayload = P;

    fn decrypt(self, key: &Self::Key) -> P {
        let vec = self.inner.to_vec();
        let (nonce, encrypted) = vec.split_at(12);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Nonce::from_slice(nonce);

        Aes256Gcm::new(&key)
            .decrypt(nonce, encrypted)
            .expect("Failed to decrypt shellcode using AES")
            .to_vec()
            .into()
    }
}

#[cfg(feature = "aes")]
pub trait AesCypherExt {
    fn aes_encrypt(self, key: &[u8; 32]) -> RawPayload;
}

#[cfg(feature = "aes")]
impl AesCypherExt for RawPayload {
    fn aes_encrypt(self, key: &[u8; 32]) -> RawPayload {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted = Aes256Gcm::new(&key)
            .encrypt(&nonce, self.as_slice())
            .expect("Failed to encrypt shellcode using AES");

        [nonce.to_vec(), encrypted].concat()
    }
}
