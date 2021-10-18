use core::convert::TryInto;

use crate::*;
use ibe::kem::SharedSecret;
use rand::{CryptoRng, Rng};

#[derive(Clone)]
pub struct KeySet {
    pub aes_key: [u8; KEY_SIZE],
    pub mac_key: [u8; MAC_SIZE],
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

/// Splits the 64-byte shared secret into two keys
pub(crate) fn derive_keys(key: &SharedSecret) -> KeySet {
    KeySet {
        aes_key: key.0[0..32].try_into().unwrap(),
        mac_key: key.0[32..64].try_into().unwrap(),
    }
}

pub(crate) fn generate_iv<R: Rng + CryptoRng>(r: &mut R) -> [u8; IV_SIZE] {
    let mut res = [0u8; IV_SIZE];
    r.fill_bytes(&mut res);
    res
}
