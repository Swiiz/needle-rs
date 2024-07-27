use std::fmt::Debug;

use crate::{Payload, Shellcode};

pub trait PayloadCypher: Payload {
    type Key;
    type InnerPayload: Payload;
    fn from_encrypted<T: Into<Vec<u8>>>(raw: T, key: Self::Key) -> Self;
    fn encrypt(payload: Self::InnerPayload, key: &Self::Key) -> Self;
    fn decrypt(&self, key: &Self::Key) -> Vec<u8>;
    fn key(&self) -> &Self::Key;
}

impl<T: PayloadCypher> Payload for T {
    fn shellcode(&self) -> Vec<u8> {
        self.decrypt(self.key())
    }
}

#[derive(Debug)]
pub struct XorCypher<T: Payload = Shellcode> {
    inner: Vec<u8>,
    key: <Self as PayloadCypher>::Key,
    _marker: std::marker::PhantomData<T>,
}

impl<'a, P: Payload> PayloadCypher for XorCypher<P> {
    type Key = u8;
    type InnerPayload = P;

    fn from_encrypted<T: Into<Vec<u8>>>(inner: T, key: Self::Key) -> Self {
        Self {
            inner: inner.into(),
            key,
            _marker: std::marker::PhantomData,
        }
    }

    fn encrypt(payload: P, key: &Self::Key) -> Self {
        let mut shellcode = payload.shellcode();
        for byte in shellcode.iter_mut() {
            *byte ^= *key;
        }
        Self::from_encrypted(shellcode, *key)
    }

    fn decrypt(&self, key: &Self::Key) -> Vec<u8> {
        self.inner.iter().map(|x| x ^ *key).collect()
    }

    fn key(&self) -> &Self::Key {
        &self.key
    }
}
