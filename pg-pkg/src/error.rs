use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;
use std::fmt::{Display, Formatter};

/// Errors that the PKG API can reply with.
///
/// These can be turned into an [`HttpResponse`].
#[derive(Debug)]
pub enum Error {
    Core(pg_core::error::Error),
    Prometheus(prometheus::Error),
    ChronologyError,
    SessionNotFound,
    UpstreamError,
    VersionError,
    DecodingError,
    NoAttributesError,
    NoTimestampError,
    ValidityError,
    Unexpected,
    ClientInvalid,
    SessionCreationError,
    APIKeyInvalid,
}

/// Errors that can occur during setup/running of the PKG.
pub enum PKGError {
    /// Error during setup, e.g., precomputations.
    Setup(String),

    /// IO error.
    StdIO(std::io::Error),

    /// Invalid version specifier.
    InvalidVersion(String),
}

impl From<std::io::Error> for PKGError {
    fn from(e: std::io::Error) -> Self {
        PKGError::StdIO(e)
    }
}

impl std::fmt::Debug for PKGError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PKGError::Setup(s) => write!(f, "error during PKG setup: {s}"),
            PKGError::StdIO(e) => write!(f, "IO error: {e}"),
            PKGError::InvalidVersion(v) => write!(f, "wrong version specifier: {v}"),
        }
    }
}

/// Show the error as an HTTP response for Actix-web.
impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        // Some variants wrap internal errors whose `Display` output may contain
        // implementation details we don't want to expose to clients (e.g. the
        // underlying Prometheus error text). Those are logged server-side in
        // full, but the HTTP response body only carries a generic message.
        let message = match self {
            Error::Prometheus(_) => {
                log::error!("internal error while handling request: {self}");
                "internal server error".to_string()
            }
            _ => format!("{self}"),
        };

        let body = json!({
            "error": true,
            "message": message,
        });

        HttpResponse::build(self.status_code()).json(body)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::Core(_) | Error::Prometheus(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::ChronologyError | Error::VersionError => StatusCode::BAD_REQUEST,
            Error::SessionNotFound => StatusCode::NOT_FOUND,
            Error::UpstreamError => StatusCode::SERVICE_UNAVAILABLE,
            Error::DecodingError => StatusCode::UNAUTHORIZED,
            Error::NoAttributesError => StatusCode::FORBIDDEN,
            Error::ValidityError => StatusCode::BAD_REQUEST,
            Error::Unexpected => StatusCode::INTERNAL_SERVER_ERROR,
            Error::ClientInvalid => StatusCode::INTERNAL_SERVER_ERROR,
            Error::NoTimestampError => StatusCode::BAD_REQUEST,
            Error::SessionCreationError => StatusCode::INTERNAL_SERVER_ERROR,
            Error::APIKeyInvalid => StatusCode::UNAUTHORIZED,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Error::Core(_) => write!(f, "core"),
            Error::ChronologyError => write!(f, "chronology error"),
            Error::SessionNotFound => write!(f, "session not found"),
            Error::UpstreamError => write!(f, "upstream error"),
            Error::VersionError => write!(f, "no such protocol version"),
            Error::DecodingError => write!(f, "JWT decoding error"),
            Error::ValidityError => write!(f, "validity exceeds maximum validity"),
            Error::NoTimestampError => write!(f, "no (valid) timestamp given"),
            Error::NoAttributesError => write!(f, "no valid attributes were disclosed"),
            Error::Prometheus(e) => write!(f, "prometheus error: {e}"),
            Error::Unexpected => write!(f, "unexpected"),
            Error::ClientInvalid => write!(f, "client couldn't be made properly"),
            Error::SessionCreationError => write!(f, "couldn't create session"),
            Error::APIKeyInvalid => write!(f, "API key is invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;

    #[actix_web::test]
    async fn prometheus_error_is_masked_in_response_body() {
        let err = Error::Prometheus(prometheus::Error::Msg(
            "sensitive internal detail".to_string(),
        ));

        // Sanity check: the full detail is still available server-side via Display.
        assert!(format!("{err}").contains("sensitive internal detail"));

        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], serde_json::json!(true));
        assert_eq!(json["message"], serde_json::json!("internal server error"));

        // The internal Prometheus detail must never reach the client.
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            !body_str.contains("sensitive internal detail"),
            "internal error detail leaked into response body: {body_str}"
        );
    }

    #[actix_web::test]
    async fn client_facing_error_message_is_preserved() {
        let err = Error::SessionNotFound;
        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], serde_json::json!(true));
        assert_eq!(json["message"], serde_json::json!("session not found"));
    }
}
