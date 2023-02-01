use actix_http::header::HeaderValue;
use actix_http::header::HttpDate;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::EntityTag;

use irmaseal_core::kem::{cgw_kv::CGWKV, IBKEM};
use irmaseal_core::Compress;
use irmaseal_core::Error;

use crate::server::ParametersData;
use crate::PKGError;

use arrayref::array_ref;
use core::hash::Hasher;
use paste::paste;
use serde::Serialize;
use std::path::Path;
use std::str::FromStr;
use std::time::SystemTime;
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
    h.write(x);
    let out = h.finish().to_be_bytes();

    base64::encode(out)
}

pub fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

pub fn now() -> Result<u64, crate::Error> {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_e| crate::Error::Unexpected)?
        .as_secs();

    Ok(n)
}

impl ParametersData {
    /// Precompute the public parameters, including cache headers.
    pub(crate) fn new<T: Serialize>(t: &T, path: Option<&str>) -> Result<ParametersData, PKGError> {
        // Precompute the serialized public parameters.
        let pp = serde_json::to_string(t)
            .map_err(|e| PKGError::Setup(format!("could not serialize public key: {e}")))?;

        // Also compute cache headers.
        let modified_raw: HttpDate = if let Some(p) = path {
            match std::fs::metadata(p).map(|m| m.modified()) {
                Ok(Ok(t)) => t,
                _ => SystemTime::now(),
            }
        } else {
            SystemTime::now()
        }
        .into();

        let last_modified = HttpDate::from_str(&modified_raw.to_string()).unwrap();

        let etag = EntityTag::new_strong(xxhash64(pp.as_bytes()));

        Ok(ParametersData {
            pp,
            last_modified,
            etag,
        })
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
