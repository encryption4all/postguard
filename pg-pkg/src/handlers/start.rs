use crate::util::{IrmaToken, IrmaUrl};
use crate::Error;
use actix_web::{web::Data, web::Json, HttpResponse};
use irma::*;
use pg_core::api::IrmaAuthRequest;

/// Maximum allowed validity (in seconds) of a JWT (1 day).
const MAX_VALIDITY: u64 = 60 * 60 * 24;

/// Default validity if no validity is specified (5 min).
const DEFAULT_VALIDITY: u64 = 60 * 5;

async fn create_irma_session(
    url: &IrmaUrl,
    irma_token: &IrmaToken,
    dr: IrmaRequest,
    validity: Option<u64>,
) -> Result<HttpResponse, Error> {
    let validity = match validity {
        Some(v) if v > MAX_VALIDITY => return Err(Error::ValidityError),
        Some(v) => v,
        None => DEFAULT_VALIDITY,
    };

    let er = ExtendedIrmaRequest {
        timeout: None,
        callback_url: None,
        validity: Some(validity),
        request: dr,
    };

    let mut builder = IrmaClientBuilder::new(&url.0).map_err(|_e| Error::ClientInvalid)?;
    if let Some(token) = irma_token.0.clone() {
        builder = builder.token_authentication(token);
    }
    let client = builder.build();

    let session = client
        .request_extended(&er)
        .await
        .or(Err(Error::SessionCreationError))?;

    Ok(HttpResponse::Ok().json(session))
}

// Starts a Yivi disclosure session.
// Builds a disclosure request for every attribute in the request's policy.
pub async fn start(
    url: Data<IrmaUrl>,
    irma_token: Data<IrmaToken>,
    value: Json<IrmaAuthRequest>,
) -> Result<HttpResponse, Error> {
    let kr = value.into_inner();

    let discons: Vec<Vec<Vec<AttributeRequest>>> = kr
        .con
        .iter()
        .map(|attr| {
            vec![vec![AttributeRequest::Compound {
                attr_type: attr.atype.clone(),
                value: attr.value.clone().filter(|v: &String| !v.is_empty()),
                not_null: true,
            }]]
        })
        .collect();

    let dr = DisclosureRequestBuilder::new().add_discons(discons).build();

    log::debug!(
        "decryption disclosure request: {}",
        serde_json::to_string_pretty(&dr).unwrap_or_default()
    );

    create_irma_session(&url, &irma_token, dr, kr.validity).await
}
