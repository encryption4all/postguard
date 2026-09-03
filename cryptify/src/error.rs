#![allow(clippy::enum_variant_names)]

use rocket::http::ContentType;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PayloadTooLargeBody {
    error: String,
    limit: &'static str,
    used_bytes: u64,
    limit_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    resets_at: Option<String>,
}

impl PayloadTooLargeBody {
    /// `used_bytes` is this upload's own byte count; there is no reset time
    /// to report for a per-upload rejection.
    pub fn per_upload(limit_bytes: u64, uploaded: u64) -> Self {
        PayloadTooLargeBody {
            error: format!(
                "Upload exceeds the per-upload limit of {} bytes",
                limit_bytes
            ),
            limit: "per_upload",
            used_bytes: uploaded,
            limit_bytes,
            resets_at: None,
        }
    }

    /// `used_bytes` is deliberately the rejected upload's own byte count,
    /// not the claimed sender's recorded usage, and `resets_at` is never
    /// set: both would disclose a claimed (unproven) sender's history
    /// through an unauthenticated finalize call (postguard#387).
    pub fn rolling_window(error: String, limit_bytes: u64, uploaded: u64) -> Self {
        PayloadTooLargeBody {
            error,
            limit: "rolling_window",
            used_bytes: uploaded,
            limit_bytes,
            resets_at: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UploadSessionNotFoundBody {
    pub error: &'static str,
    pub uuid: String,
    pub reason: &'static str,
}

#[derive(Debug)]
pub enum Error {
    BadRequest(Option<String>),
    /// 401 — the request did not present a valid API key on an endpoint
    /// that requires one. Distinct from the upload flow, which degrades a
    /// missing/invalid key to the default tier rather than rejecting.
    Unauthorized(Option<String>),
    /// 404 — the resource (e.g. the email template for a validated API
    /// key) does not exist. Carries an optional human-readable message.
    NotFound(Option<String>),
    UnprocessableEntity(Option<String>),
    InternalServerError(Option<String>),
    PayloadTooLarge(PayloadTooLargeBody),
    /// 503 — pg-pkg was unreachable for the full retry budget while
    /// validating an API key. Returned when the upload exceeds the default
    /// tier and we couldn't confirm the caller is entitled to the higher
    /// tier. Smaller uploads degrade silently to the default tier.
    ServiceUnavailable(Option<String>),
    UploadSessionNotFound(UploadSessionNotFoundBody),
}

impl Error {
    pub fn upload_session_not_found(uuid: impl Into<String>, reason: &'static str) -> Self {
        Error::UploadSessionNotFound(UploadSessionNotFoundBody {
            error: "upload_session_not_found",
            uuid: uuid.into(),
            reason,
        })
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> response::Result<'o> {
        match self {
            Error::BadRequest(e) => response::status::BadRequest(e).respond_to(request),
            Error::Unauthorized(e) => response::status::Custom::<String>(
                rocket::http::Status::Unauthorized,
                e.unwrap_or_else(|| "".to_owned()),
            )
            .respond_to(request),
            Error::NotFound(e) => response::status::Custom::<String>(
                rocket::http::Status::NotFound,
                e.unwrap_or_else(|| "".to_owned()),
            )
            .respond_to(request),
            // response::status::Custom apparently doesn't support Option<R>
            Error::UnprocessableEntity(e) => response::status::Custom::<String>(
                rocket::http::Status::UnprocessableEntity,
                e.unwrap_or_else(|| "".to_owned()),
            )
            .respond_to(request),
            Error::InternalServerError(e) => response::status::Custom::<String>(
                rocket::http::Status::InternalServerError,
                e.unwrap_or_else(|| "".to_owned()),
            )
            .respond_to(request),
            Error::PayloadTooLarge(body) => {
                response::Response::build_from(Json(body).respond_to(request)?)
                    .status(rocket::http::Status::PayloadTooLarge)
                    .header(ContentType::JSON)
                    .ok()
            }
            Error::ServiceUnavailable(e) => response::status::Custom::<String>(
                rocket::http::Status::ServiceUnavailable,
                e.unwrap_or_else(|| "".to_owned()),
            )
            .respond_to(request),
            Error::UploadSessionNotFound(body) => {
                response::Response::build_from(Json(body).respond_to(request)?)
                    .status(rocket::http::Status::NotFound)
                    .header(ContentType::JSON)
                    .ok()
            }
        }
    }
}
