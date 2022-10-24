use actix_http::header::HeaderValue;
use actix_web::dev::ServiceRequest;
use arrayref::array_ref;
use core::hash::Hasher;
use irmaseal_core::kem::{cgw_kv::CGWKV, IBKEM};
use irmaseal_core::Compress;
use irmaseal_core::Error;
use paste::paste;
use std::path::Path;
use twox_hash::XxHash64;

pub(crate) const PG_CLIENT_HEADER: &str = "X-POSTGUARD-CLIENT-VERSION";

pub(crate) fn client_version(req: &ServiceRequest) -> String {
    if let Some(Ok(x)) = req.headers().get(PG_CLIENT_HEADER).map(HeaderValue::to_str) {
        x.to_string()
    } else {
        String::from("unknown")
    }
}

pub(crate) fn xxhash64(x: &[u8]) -> String {
    let mut h = XxHash64::with_seed(0);
    h.write(&x);
    let out = h.finish().to_be_bytes();
    base64::encode(&out)
}

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
            open_ct(<$scheme as IBKEM>::Pk::from_bytes(bytes)).ok_or(Error::FormatViolation)
        }

        pub fn [<$scheme:lower _read_sk>](path: impl AsRef<Path>) -> Result<<$scheme as IBKEM>::Sk, Error> {
            const LENGTH: usize = $scheme::SK_BYTES;

            let bytes = std::fs::read(path).unwrap();
            if bytes.len() != LENGTH {
                return Err(Error::FormatViolation);
            }

            let bytes = array_ref![&bytes, 0, LENGTH];
            open_ct(<$scheme as IBKEM>::Sk::from_bytes(bytes)).ok_or(Error::FormatViolation)
        }
        }
    };
}

read_keypair!(CGWKV);
