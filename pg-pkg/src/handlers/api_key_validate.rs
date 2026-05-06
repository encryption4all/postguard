//! `GET /v2/api-key/validate` — confirms a `PG-…` API key is valid and
//! returns the associated tenant identity. Used by sibling services (e.g.
//! cryptify) that need to gate per-tenant behaviour on a validated key
//! without going through signing-key issuance.
//!
//! Auth: gated by `ApiKeyGuard` + `Auth::new(_, AuthType::Key)`. Reaching
//! this handler means the bearer token already passed `business_api_keys`
//! lookup; this handler only serializes the result.

use actix_web::{HttpMessage, HttpRequest, HttpResponse};
use serde::Serialize;

use crate::middleware::auth::ApiKeyData;

#[derive(Debug, Serialize)]
pub struct ApiKeyValidateResponse {
    /// `organizations.id` — stable per-tenant identifier.
    pub tenant_id: String,
    /// Best-effort organisation display name. May be `None` when the
    /// business portal has no name configured for the tenant.
    pub organisation_name: Option<String>,
}

pub async fn api_key_validate(req: HttpRequest) -> Result<HttpResponse, crate::Error> {
    let key_data = req
        .extensions()
        .get::<ApiKeyData>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    req.extensions_mut().clear();

    Ok(HttpResponse::Ok().json(ApiKeyValidateResponse {
        tenant_id: key_data.org_id,
        organisation_name: key_data.organisation_name,
    }))
}
