use arrayref::array_ref;
#[cfg(feature = "v1")]
use ibe::kem::kiltz_vahlis_one::KV1;
use ibe::kem::{cgw_fo::CGWFO, IBKEM};
use ibe::Compress;
use irmaseal_core::Error;
use paste::paste;
use std::path::Path;

pub fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

macro_rules! read_keypair {
    ($scheme: ident) => {
        paste! {
        pub fn [<$scheme:lower _read_pk>](path: impl AsRef<Path>) -> Result<<$scheme as IBKEM>::Pk, Error> {
            const LENGTH: usize = $scheme::PK_BYTES;

            let bytes = std::fs::read(path).unwrap();
            if bytes.len() != LENGTH {
                return Err(Error::FormatViolation);
            }

            let bytes = array_ref![&bytes, 0, LENGTH];
            Ok(open_ct(<$scheme as IBKEM>::Pk::from_bytes(bytes)).ok_or(Error::FormatViolation)?)
        }

        pub fn [<$scheme:lower _read_sk>](path: impl AsRef<Path>) -> Result<<$scheme as IBKEM>::Sk, Error> {
            const LENGTH: usize = $scheme::SK_BYTES;

            let bytes = std::fs::read(path).unwrap();
            if bytes.len() != LENGTH {
                return Err(Error::FormatViolation);
            }

            let bytes = array_ref![&bytes, 0, LENGTH];
            Ok(open_ct(<$scheme as IBKEM>::Sk::from_bytes(bytes)).ok_or(Error::FormatViolation)?)
        }
        }
    };
}

read_keypair!(CGWFO);

#[cfg(feature = "v1")]
read_keypair!(KV1);
