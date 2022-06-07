use crate::*;
use ibe::kem::IBKEM;
use rand::{CryptoRng, Rng};

/// Maps schemes to protocol version.
pub fn version<K: IBKEM>() -> Result<&'static str, Error> {
    match K::IDENTIFIER {
        "kv1" => Ok("v1"),
        "cgwkv" => Ok("v2"),
        _ => Err(Error::IncorrectVersion),
    }
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

pub(crate) fn generate_iv<R: Rng + CryptoRng>(r: &mut R) -> [u8; DEFAULT_IV_SIZE] {
    let mut res = [0u8; DEFAULT_IV_SIZE];
    r.fill_bytes(&mut res);
    res
}
