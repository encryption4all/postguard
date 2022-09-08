use crate::error::Error;
use ibe::kem::IBKEM;

/// Maps schemes to protocol version.
pub fn version<K: IBKEM>() -> Result<&'static str, Error> {
    match K::IDENTIFIER {
        "kv1" => Ok("v1"),
        "cgwkv" => Ok("v2"),
        _ => Err(Error::IncorrectSchemeVersion),
    }
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}
