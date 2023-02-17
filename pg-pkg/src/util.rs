use actix_http::header::HeaderValue;
use actix_http::header::HttpDate;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::EntityTag;

use pg_core::kem::{cgw_kv::CGWKV, IBKEM};
use pg_core::Compress;

use crate::error::PKGError;
use crate::server::ParametersData;

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

pub fn current_time_u64() -> Result<u64, crate::Error> {
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
            pub(crate) fn [<$scheme:lower _read_key_pair>](pk_path: impl AsRef<Path>, sk_path: impl AsRef<Path>) -> Result<(<$scheme as IBKEM>::Pk, <$scheme as IBKEM>::Sk), PKGError> {
                const PK_LENGTH: usize = $scheme::PK_BYTES;
                const SK_LENGTH: usize = $scheme::SK_BYTES;

                let pk_bytes = std::fs::read(pk_path).unwrap();
                if pk_bytes.len() != PK_LENGTH {
                    return Err(PKGError::Setup("wrong pk length".to_string()));
                }

                let pk_bytes = array_ref![&pk_bytes, 0, PK_LENGTH];
                let pk = open_ct(<$scheme as IBKEM>::Pk::from_bytes(pk_bytes)).ok_or(PKGError::Setup("could not read pk".to_string()))?;

                let sk_bytes = std::fs::read(sk_path).unwrap();
                if sk_bytes.len() != SK_LENGTH {
                    return Err(PKGError::Setup("wrong sk length".to_string()));
                }

                let sk_bytes = array_ref![&sk_bytes, 0, SK_LENGTH];
                let sk = open_ct(<$scheme as IBKEM>::Sk::from_bytes(sk_bytes)).ok_or(PKGError::Setup("could not read sk".to_string()))?;

                Ok((pk, sk))
            }
        }
    };
}

read_keypair!(CGWKV);

pub(crate) fn gg_read_key_pair(
    pk_path: impl AsRef<Path>,
    sk_path: impl AsRef<Path>,
) -> Result<(pg_core::ibs::gg::PublicKey, pg_core::ibs::gg::SecretKey), PKGError> {
    let pk_bytes = std::fs::read(pk_path)?;
    let pk: pg_core::ibs::gg::PublicKey = bincode::deserialize(&pk_bytes)
        .map_err(|e| PKGError::Setup(format!("could not deserialize ibs pk: {e}")))?;

    let sk_bytes = std::fs::read(sk_path)?;
    let sk: pg_core::ibs::gg::SecretKey = bincode::deserialize(&sk_bytes)
        .map_err(|e| PKGError::Setup(format!("could not deserialize ibs sk: {e}")))?;

    Ok((pk, sk))
}
