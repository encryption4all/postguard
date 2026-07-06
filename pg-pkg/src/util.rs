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
use serde::Serialize;
use std::path::Path;
use std::str::FromStr;
use std::time::SystemTime;
use twox_hash::XxHash64;

pub(crate) const PG_CLIENT_HEADER: &str = "X-POSTGUARD-CLIENT-VERSION";

// Strongly-typed wrappers for IRMA URL and token so actix-web can store both as distinct Data<T>.
#[derive(Debug, Clone)]
pub(crate) struct IrmaUrl(pub String);

#[derive(Debug, Clone)]
pub(crate) struct IrmaToken(pub Option<String>);

/// Length of an IRMA/Yivi requestor session token.
const SESSION_TOKEN_LEN: usize = 20;

/// Returns `true` if `token` is a well-formed IRMA/Yivi session token.
///
/// IRMA/Yivi requestor session tokens are 20-character base62 strings made up
/// exclusively of ASCII letters and digits (e.g. `ELMExi5iauWYHzbH7gwU`); they
/// are **not** UUIDs.
///
/// The session `{token}` path parameter is interpolated verbatim into the
/// upstream IRMA server URL, so it must be validated against this fixed shape
/// before use. Restricting it to a fixed-length ASCII-alphanumeric allowlist
/// keeps URL metacharacters (`/`, `..`, `?`, `#`, ...) and any other
/// attacker-controlled input out of the constructed URL.
pub(crate) fn is_valid_session_token(token: &str) -> bool {
    token.len() == SESSION_TOKEN_LEN && token.bytes().all(|c| c.is_ascii_alphanumeric())
}

pub(crate) fn client_version(req: &ServiceRequest) -> String {
    if let Some(Ok(x)) = req.headers().get(PG_CLIENT_HEADER).map(HeaderValue::to_str) {
        x.to_string()
    } else {
        String::from("unknown")
    }
}

pub(crate) fn xxhash64(x: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let mut h = XxHash64::with_seed(0);
    h.write(x);
    let out = h.finish().to_be_bytes();

    general_purpose::STANDARD_NO_PAD.encode(out)
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

pub(crate) fn cgwkv_read_key_pair(
    pk_path: impl AsRef<Path>,
    sk_path: impl AsRef<Path>,
) -> Result<(<CGWKV as IBKEM>::Pk, <CGWKV as IBKEM>::Sk), PKGError> {
    const PK_LENGTH: usize = CGWKV::PK_BYTES;
    const SK_LENGTH: usize = CGWKV::SK_BYTES;

    let pk_bytes = std::fs::read(&pk_path)
        .map_err(|e| PKGError::Setup(format!("could not read public key file: {e}")))?;
    if pk_bytes.len() != PK_LENGTH {
        return Err(PKGError::Setup("wrong pk length".to_string()));
    }

    let pk_bytes = array_ref![&pk_bytes, 0, PK_LENGTH];
    let pk = open_ct(<CGWKV as IBKEM>::Pk::from_bytes(pk_bytes))
        .ok_or(PKGError::Setup("could not read pk".to_string()))?;

    let sk_bytes = std::fs::read(&sk_path)
        .map_err(|e| PKGError::Setup(format!("could not read secret key file: {e}")))?;
    if sk_bytes.len() != SK_LENGTH {
        return Err(PKGError::Setup("wrong sk length".to_string()));
    }

    let sk_bytes = array_ref![&sk_bytes, 0, SK_LENGTH];
    let sk = open_ct(<CGWKV as IBKEM>::Sk::from_bytes(sk_bytes))
        .ok_or(PKGError::Setup("could not read sk".to_string()))?;

    Ok((pk, sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PKGError;

    #[test]
    fn cgwkv_read_key_pair_missing_files_returns_error_not_panic() {
        let result = cgwkv_read_key_pair("/nonexistent/pk", "/nonexistent/sk");
        match result {
            Err(PKGError::Setup(msg)) => {
                assert!(
                    msg.contains("public key file"),
                    "expected message about public key file, got: {msg}"
                );
            }
            other => panic!("expected Setup error, got {other:?}"),
        }
    }

    #[test]
    fn is_valid_session_token_accepts_real_tokens() {
        // Realistic 20-char base62 IRMA/Yivi requestor tokens (from the
        // irmars crate's own fixtures), plus all-letters/all-digits edges.
        for token in [
            "ELMExi5iauWYHzbH7gwU",
            "bVqg9btHRhiMvEWs8axQ",
            "5bTpPRXctenYGGsZVe3x",
            "abcdefghijklmnopqrst",
            "01234567890123456789",
        ] {
            assert!(
                is_valid_session_token(token),
                "expected {token} to be accepted"
            );
        }
    }

    #[test]
    fn is_valid_session_token_rejects_malformed_tokens() {
        for token in [
            "",
            // Wrong length (too short / too long).
            "ELMExi5iauWYHzbH7gw",
            "ELMExi5iauWYHzbH7gwUX",
            // A UUID is the wrong shape (36 chars, contains hyphens).
            "de305d54-75b4-431b-adb2-eb6b9e546013",
            // Non-alphanumeric characters inside an otherwise 20-char token.
            "ELMExi5iauWYHzbH7gw.",
            "ELMExi5iauWYHzbH7gw_",
            // URL metacharacters / path-traversal / injection attempts.
            "../../session/other/",
            "a/b/c/d/e/f/g/h/i/jk",
            "a?b=cdefghijklmnopqr",
            "a#bcdefghijklmnopqrs",
            "ELMExi5iauWYHzbH7gwU/../admin",
        ] {
            assert!(
                !is_valid_session_token(token),
                "expected {token} to be rejected"
            );
        }
    }

    #[test]
    fn gg_read_key_pair_missing_files_returns_error_not_panic() {
        let result = gg_read_key_pair("/nonexistent/pk", "/nonexistent/sk");
        match result {
            Err(PKGError::StdIO(_)) => {}
            other => panic!("expected StdIO error, got {other:?}"),
        }
    }
}

pub(crate) fn gg_read_key_pair(
    pk_path: impl AsRef<Path>,
    sk_path: impl AsRef<Path>,
) -> Result<(pg_core::ibs::gg::PublicKey, pg_core::ibs::gg::SecretKey), PKGError> {
    let pk_bytes = std::fs::read(pk_path)?;
    let pk: pg_core::ibs::gg::PublicKey = pg_core::bincode_compat::deserialize(&pk_bytes)
        .map_err(|e| PKGError::Setup(format!("could not deserialize ibs pk: {e}")))?;

    let sk_bytes = std::fs::read(sk_path)?;
    let sk: pg_core::ibs::gg::SecretKey = pg_core::bincode_compat::deserialize(&sk_bytes)
        .map_err(|e| PKGError::Setup(format!("could not deserialize ibs sk: {e}")))?;

    Ok((pk, sk))
}
