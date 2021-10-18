use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use std::fmt::{Display, Formatter};

/// Show the error as an HTTP response for Actix-web.
impl ResponseError for Error {
    fn render_response(&self) -> HttpResponse {
        let body = json!({
            "error": true,
            "message": format!("{}", self),
        });

        let mut response = match self {
            Error::Core(_) => HttpResponse::InternalServerError(),
            Error::ChronologyError => HttpResponse::BadRequest(),
            Error::SessionNotFound => HttpResponse::NotFound(),
            Error::UpstreamError => HttpResponse::ServiceUnavailable(),
            Error::VersionError => HttpResponse::BadRequest(),
            Error::Unexpected => HttpResponse::InternalServerError(),
        };

        response.json(body)
    }
}

#[derive(Debug)]
pub enum Error {
    Core(irmaseal_core::Error),
    ChronologyError,
    SessionNotFound,
    UpstreamError,
    VersionError,
    Unexpected,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::Core(_) => "core",
                Error::ChronologyError => "chronology error",
                Error::SessionNotFound => "session not found",
                Error::UpstreamError => "upstream error",
                Error::VersionError => "no such protocol version",
                Error::Unexpected => "unexpected",
            }
        )
    }
}
