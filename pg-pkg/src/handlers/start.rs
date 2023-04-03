use crate::Error;
use actix_web::{web::Data, web::Json, HttpResponse};
use irma::*;
use pg_core::api::IrmaAuthRequest;

/// Maximum allowed valitidy (in seconds) of a JWT (1 day).
const MAX_VALIDITY: u64 = 60 * 60 * 24;

/// Default validity if no validity is specified (5 min).
const DEFAULT_VALIDITY: u64 = 60 * 5;

pub async fn start(
    url: Data<String>,
    value: Json<IrmaAuthRequest>,
) -> Result<HttpResponse, crate::Error> {
    let irma_url = url.get_ref().clone();
    let kr = value.into_inner();

    let dr = DisclosureRequestBuilder::new()
        .add_discons(
            kr.con
                .iter()
                .map(|attr| {
                    vec![vec![AttributeRequest::Compound {
                        attr_type: attr.atype.clone(),
                        value: attr.value.clone(),
                        not_null: true,
                    }]]
                })
                .collect(),
        )
        .build();

    let validity = match kr.validity {
        Some(validity) if validity > MAX_VALIDITY => Err(Error::ValidityError),
        Some(validity) => Ok(validity),
        None => Ok(DEFAULT_VALIDITY),
    }?;

    let er = ExtendedIrmaRequest {
        timeout: None,
        callback_url: None,
        validity: Some(validity),
        request: dr,
    };

    let client = IrmaClientBuilder::new(&irma_url)
        .map_err(|_e| Error::Unexpected)?
        .build();

    let session = client
        .request_extended(&er)
        .await
        .or(Err(crate::Error::Unexpected))?;

    Ok(HttpResponse::Ok().json(session))
}
