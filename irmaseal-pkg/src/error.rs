use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use irma::{ProofStatus, SessionStatus, SessionType};
use serde_json::json;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Core(irmaseal_core::Error),
    SessionError((SessionType, SessionStatus, Option<ProofStatus>)),
    ChronologyError,
    SessionNotFound,
    UpstreamError,
    VersionError,
    DecodingError,
    ValidityError,
    Unexpected,
}

/// Show the error as an HTTP response for Actix-web.
impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let body = json!({
            "error": true,
            "message": format!("{}", self),
        });

        HttpResponse::build(self.status_code()).json(body)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::Core(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SessionError(_) => StatusCode::FORBIDDEN,
            Error::ChronologyError | Error::VersionError => StatusCode::BAD_REQUEST,
            Error::SessionNotFound => StatusCode::NOT_FOUND,
            Error::UpstreamError => StatusCode::SERVICE_UNAVAILABLE,
            Error::DecodingError => StatusCode::UNAUTHORIZED,
            Error::ValidityError => StatusCode::BAD_REQUEST,
            Error::Unexpected => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::Core(_) => "core",
                Error::SessionError((st, ss, ops)) =>
                    &format!("session type: {st:?}, session status: {ss:?}, proof status: {ops:?}"),
                Error::ChronologyError => "chronology error",
                Error::SessionNotFound => "session not found",
                Error::UpstreamError => "upstream error",
                Error::VersionError => "no such protocol version",
                Error::DecodingError => "JWT decoding error",
                Error::ValidityError => "validity exceeds maximum validity",
                Error::Unexpected => "unexpected",
            }
        )
    }
}
