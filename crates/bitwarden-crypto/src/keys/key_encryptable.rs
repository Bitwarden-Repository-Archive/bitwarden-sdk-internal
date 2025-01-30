use std::{collections::HashMap, hash::Hash, sync::Arc};

use rayon::prelude::*;
use uuid::Uuid;

use crate::{error::Result, CryptoError, SymmetricCryptoKey};

pub trait KeyContainer: Send + Sync {
    fn get_key(&self, org_id: &Option<Uuid>) -> Result<&SymmetricCryptoKey, CryptoError>;
}

impl<T: KeyContainer> KeyContainer for Arc<T> {
    fn get_key(&self, org_id: &Option<Uuid>) -> Result<&SymmetricCryptoKey, CryptoError> {
        self.as_ref().get_key(org_id)
    }
}

pub trait LocateKey {
    fn locate_key<'a>(
        &self,
        enc: &'a dyn KeyContainer,
        org_id: &Option<Uuid>,
    ) -> Result<&'a SymmetricCryptoKey, CryptoError> {
        enc.get_key(org_id)
    }
}

mod private {
    // We can't easily add blanket impls for Encodable and Decodable to ensure the reverse impls are available,
    // but we can mark the traits as sealed to ensure that only the intended types can implement them.
    pub trait Sealed {}
    impl Sealed for Vec<u8> {}
    impl Sealed for &[u8] {}
    impl Sealed for String {}
    impl Sealed for &str {}
}

pub trait Encodable<To>: private::Sealed {
    fn encode(self) -> To;
}

pub trait Decodable<To>: private::Sealed {
    fn try_decode(self) -> Result<To, CryptoError>;
}

impl Encodable<Vec<u8>> for Vec<u8> {
    fn encode(self) -> Vec<u8> {
        self
    }
}

impl Encodable<Vec<u8>> for &[u8] {
    fn encode(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Decodable<Vec<u8>> for Vec<u8> {
    fn try_decode(self) -> Result<Vec<u8>, CryptoError> {
        Ok(self)
    }
}

impl Encodable<Vec<u8>> for String {
    fn encode(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl Encodable<Vec<u8>> for &str {
    fn encode(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Decodable<String> for Vec<u8> {
    fn try_decode(self) -> Result<String, CryptoError> {
        String::from_utf8(self).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

pub trait CryptoKey {}

pub trait KeyEncryptable<Key: CryptoKey, Output> {
    fn encrypt_with_key(self, key: &Key) -> Result<Output>;
}

pub trait KeyDecryptable<Key: CryptoKey, Output> {
    fn decrypt_with_key(&self, key: &Key) -> Result<Output>;
}

impl<T: KeyEncryptable<Key, Output>, Key: CryptoKey, Output> KeyEncryptable<Key, Option<Output>>
    for Option<T>
{
    fn encrypt_with_key(self, key: &Key) -> Result<Option<Output>> {
        self.map(|e| e.encrypt_with_key(key)).transpose()
    }
}

impl<T: KeyDecryptable<Key, Output>, Key: CryptoKey, Output> KeyDecryptable<Key, Option<Output>>
    for Option<T>
{
    fn decrypt_with_key(&self, key: &Key) -> Result<Option<Output>> {
        self.as_ref().map(|e| e.decrypt_with_key(key)).transpose()
    }
}

/*
impl<T: KeyEncryptable<Key, Output>, Key: CryptoKey, Output> KeyEncryptable<Key, Output>
    for Box<T>
{
    fn encrypt_with_key(self, key: &Key) -> Result<Output> {
        (*self).encrypt_with_key(key)
    }
}*/

impl<T: KeyDecryptable<Key, Output>, Key: CryptoKey, Output> KeyDecryptable<Key, Output>
    for Box<T>
{
    fn decrypt_with_key(&self, key: &Key) -> Result<Output> {
        (**self).decrypt_with_key(key)
    }
}

impl<
        T: KeyEncryptable<Key, Output> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
    > KeyEncryptable<Key, Vec<Output>> for Vec<T>
{
    fn encrypt_with_key(self, key: &Key) -> Result<Vec<Output>> {
        self.into_par_iter()
            .map(|e| e.encrypt_with_key(key))
            .collect()
    }
}

impl<
        T: KeyDecryptable<Key, Output> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
    > KeyDecryptable<Key, Vec<Output>> for Vec<T>
{
    fn decrypt_with_key(&self, key: &Key) -> Result<Vec<Output>> {
        self.into_par_iter()
            .map(|e| e.decrypt_with_key(key))
            .collect()
    }
}

impl<
        T: KeyEncryptable<Key, Output> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
        Id: Hash + Eq + Send + Sync,
    > KeyEncryptable<Key, HashMap<Id, Output>> for HashMap<Id, T>
{
    fn encrypt_with_key(self, key: &Key) -> Result<HashMap<Id, Output>> {
        self.into_par_iter()
            .map(|(id, e)| Ok((id, e.encrypt_with_key(key)?)))
            .collect()
    }
}

impl<
        T: KeyDecryptable<Key, Output> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
        Id: Hash + Eq + Copy + Send + Sync,
    > KeyDecryptable<Key, HashMap<Id, Output>> for HashMap<Id, T>
{
    fn decrypt_with_key(&self, key: &Key) -> Result<HashMap<Id, Output>> {
        self.into_par_iter()
            .map(|(id, e)| Ok((*id, e.decrypt_with_key(key)?)))
            .collect()
    }
}
