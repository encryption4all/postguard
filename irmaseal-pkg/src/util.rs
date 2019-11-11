use arrayref::array_ref;
use ibe::kiltz_vahlis_one::{PublicKey, SecretKey};
use irmaseal_core::Error;

pub fn read_pk() -> Result<PublicKey, Error> {
    const LENGTH: usize = 25056;

    let bytes = std::fs::read("./pkg.pub").unwrap();
    if bytes.len() != LENGTH {
        return Err(Error::FormatViolation);
    }

    let bytes = array_ref![&bytes, 0, LENGTH];
    Ok(open_ct(PublicKey::from_bytes(bytes)).ok_or(Error::FormatViolation)?)
}

pub fn read_sk() -> Result<SecretKey, Error> {
    const LENGTH: usize = 48;

    let bytes = std::fs::read("./pkg.sec").unwrap();
    if bytes.len() != LENGTH {
        return Err(Error::FormatViolation);
    }

    let bytes = array_ref![&bytes, 0, LENGTH];
    Ok(open_ct(SecretKey::from_bytes(bytes)).ok_or(Error::FormatViolation)?)
}

pub fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}
