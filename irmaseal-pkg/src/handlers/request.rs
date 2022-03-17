use crate::Error;
use actix_web::{web::Data, web::Json, HttpResponse};
use irma::*;
use irmaseal_core::api::KeyRequest;

const MAX_VALIDITY: u64 = 60 * 60 * 24;

pub async fn request(
    url: Data<String>,
    value: Json<KeyRequest>,
) -> Result<HttpResponse, crate::Error> {
    let irma_url = url.get_ref().clone();
    let kr = value.into_inner();

    let dr = DisclosureRequestBuilder::new()
        .add_discon(vec![kr
            .con
            .iter()
            .map(|attr| AttributeRequest::Compound {
                attr_type: attr.atype.clone(),
                value: attr.value.clone(),
                not_null: true,
            })
            .collect()])
        .build();

    // Might be better to respond with error.
    let validity_checked = kr.validity.map(|v| std::cmp::min(v, MAX_VALIDITY));

    let er = ExtendedIrmaRequest {
        timeout: None,
        callback_url: None,
        validity: validity_checked,
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
