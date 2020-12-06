//!Minimalistic encrypted storage for arbitrary values.

#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

use std::collections::BTreeMap;
use xxhash_rust::xxh3::xxh3_128;

use core::ptr;

mod enc;

///Secure storage API
///
///Values are stored in memory encrypted, user can save storages manually
///and lately restore it using `serde`
///
///`Key` is stored as hash, while `Value` is stored as encrypted bytes.
pub struct Store {
    ///Values are stored as hash(key), encrypted data(value)
    ///
    ///Technically it is possible to reverse hash, but in practice it is unlikely to happen.
    ///Only value itself is supposed to be sensitive in our case
    inner: BTreeMap<u128, Vec<u8>>,
    enc: enc::Manager,
}

impl Store {
    #[inline]
    ///Creates new instance using creds.
    ///
    ///Parameters:
    ///
    ///- `user` - user specific information that can distinguish him from others.
    ///- `pass` - can be any number of arbitrary bytes except it MUST NOT be zero length.
    pub fn new(user: &[u8], pass: &[u8]) -> Self {
        Self::from_inner(Default::default(), user, pass)
    }

    #[inline]
    ///Creates new instance using provided storage and pass.
    ///
    ///Parameters:
    ///
    ///- `storage` - already initialized storage, only can work with storage that is returned by `Self::inner`.
    ///- `user`    - user specific information that can distinguish him from others.
    ///- `pass`    - can be any number of arbitrary bytes except it MUST NOT be zero length.
    pub fn from_inner(inner: BTreeMap<u128, Vec<u8>>, user: &[u8], pass: &[u8]) -> Self {
        assert_ne!(user.len(), 0);
        assert_ne!(pass.len(), 0);

        Self {
            inner,
            enc: enc::Manager::new(enc::generate_key(user, pass))
        }
    }

    #[inline]
    ///Accesses inner representation of storage, allowing to serialize it.
    pub fn inner(&self) -> &BTreeMap<u128, Vec<u8>> {
        &self.inner
    }

    #[inline]
    ///Consumes self, returning underlying storage.
    pub fn into_inner(self) -> BTreeMap<u128, Vec<u8>> {
        self.inner
    }

    #[inline]
    ///Returns number of key-value pairs
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn inner_get_to(&self, key: u128, dest: &mut [u8]) -> Result<usize, ()> {
        match self.inner.get(&key) {
            Some(value) => {
                if value.len() > dest.len() {
                    return Ok(0);
                }

                unsafe {
                    ptr::copy_nonoverlapping(value.as_ptr(), dest.as_mut_ptr(), value.len());
                }

                match self.enc.decrypt(key, &mut dest[..value.len()]) {
                    Some(written) => {
                        Ok(written.len())
                    },
                    None => Err(())
                }
            },
            None => Err(())
        }
    }

    fn inner_get_to_vec(&self, key: u128, dest: &mut Vec<u8>) -> Result<usize, ()> {
        match self.inner.get(&key) {
            Some(value) => {
                dest.truncate(0);
                dest.extend_from_slice(&value);
                match self.enc.decrypt(key, dest) {
                    Some(written) => {
                        let len = written.len();
                        dest.truncate(len);
                        dest.shrink_to_fit();
                        Ok(dest.len())
                    },
                    None => Err(())
                }
            },
            None => Err(()),
        }
    }

    #[inline]
    ///Retrieves value for `key`, storing decrypted value in `dest`.
    ///
    ///Returns `Err` when key doesn't exist or user has no permission to read it.
    ///Otherwise returns number of bytes written, or '0' in case of insufficient storage.
    pub fn get_to(&self, key: &[u8], dest: &mut [u8]) -> Result<usize, ()> {
        let key = xxh3_128(key).to_le();

        self.inner_get_to(key, dest)
    }

    #[inline]
    ///Retrieves value for `key` to store in `dest`, resulting in it being overwritten.
    ///
    ///Returns `Err` when key doesn't exist or user has no permission to read it.
    ///Otherwise returns number of bytes written.
    pub fn get_to_vec(&self, key: &[u8], dest: &mut Vec<u8>) -> Result<usize, ()> {
        let key = xxh3_128(key).to_le();

        self.inner_get_to_vec(key, dest)
    }

    #[inline]
    ///Retrieves value for `key`
    ///
    ///Returns `None` if decryption failed.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        match self.get_to_vec(key, &mut result) {
            Ok(_) => Some(result),
            Err(_) => None,
        }
    }

    ///Inserts new owned `value` for `key`, returning previous one, if any.
    pub fn insert_owned(&mut self, key: &[u8], mut value: Vec<u8>) -> Option<Vec<u8>> {
        assert_ne!(value.len(), 0);

        let key = xxh3_128(key).to_le();

        assert!(self.enc.encrypt(key, &mut value));

        self.inner.insert(key, value).and_then(|mut value| {
            match self.enc.decrypt(key, &mut value) {
                Some(written) => {
                    let len = written.len();
                    value.truncate(len);
                    value.shrink_to_fit();
                    Some(value)
                },
                None => None
            }
        })
    }

    #[inline]
    ///Inserts new `value` for `key`, returning previous one, if any.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        self.insert_owned(key, value.to_owned())
    }

    ///Extracts value under `key` to specified `dest`
    ///
    ///Returns `Err` when key doesn't exist, or user has no permission to read it.
    ///Otherwise returns number of bytes written, or '0' in case of insufficient storage.
    ///
    ///Note that value is removed only if `Ok(size) >= Ok(1)`
    pub fn remove_to(&mut self, key: &[u8], dest: &mut [u8]) -> Result<usize, ()> {
        let key = xxh3_128(key).to_le();

        match self.inner_get_to(key, dest) {
            Ok(0) => Ok(0),
            Ok(result) => {
                let _ = self.inner.remove(&key);
                Ok(result)
            },
            Err(_) => Err(()),
        }
    }

    ///Extracts value under `key` to specified `dest`
    ///
    ///Returns `Err` when key doesn't exist, or user has no permission to read it.
    ///Otherwise returns number of bytes written.
    pub fn remove_to_vec(&mut self, key: &[u8], dest: &mut Vec<u8>) -> Result<usize, ()> {
        let key = xxh3_128(key).to_le();

        match self.inner_get_to_vec(key, dest) {
            Ok(result) => {
                let _ = self.inner.remove(&key);
                Ok(result)
            },
            Err(_) => Err(()),
        }
    }

    #[inline]
    ///Removes `key`, returning previous value, if any.
    ///
    ///Failing to decrypt, doesn't remove value.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        match self.remove_to_vec(key, &mut result) {
            Ok(_) => Some(result),
            Err(_) => None,
        }
    }

    #[inline]
    ///Removes `key`, returning whether it was set previously.
    ///
    ///Note that it only removes value, without checking if you can read it.
    pub fn remove_key(&mut self, key: &[u8]) -> bool {
        let key = xxh3_128(key).to_le();
        self.inner.remove(&key).is_some()
    }
}
