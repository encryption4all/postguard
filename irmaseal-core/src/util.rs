use core::convert::TryInto;

use crate::*;
use ibe::kem::{SharedSecret, IBKEM};
use rand::{CryptoRng, Rng};

/// Maps schemes to protocol version
pub fn version<K: IBKEM>() -> Result<&'static str, Error> {
    match K::IDENTIFIER {
        "kv1" => Ok("v1"),
        "cgwkv" => Ok("v2"),
        _ => Err(Error::IncorrectVersion),
    }
}

#[derive(Debug, Clone)]
pub struct KeySet {
    pub aes_key: [u8; KEY_SIZE],
    pub mac_key: [u8; KEY_SIZE],
}

/// Splits the 32-byte shared secret into two 16-byte keys.
pub(crate) fn derive_keys(key: &SharedSecret) -> KeySet {
    let (aes_key, mac_key) = key.0.split_at(KEY_SIZE);
    KeySet {
        aes_key: aes_key.try_into().unwrap(),
        mac_key: mac_key.try_into().unwrap(),
    }
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

pub(crate) fn generate_iv<R: Rng + CryptoRng>(r: &mut R) -> [u8; IV_SIZE] {
    let mut res = [0u8; IV_SIZE];
    r.fill_bytes(&mut res);
    res
}
