use actix_web::web::{Data, HttpResponse, Json};
use irmaseal_core::api::KeyRequest;

use crate::Error;
use irma::*;

pub async fn request(
    url: Data<String>,
    value: Json<KeyRequest>,
) -> Result<HttpResponse, crate::Error> {
    let irma_url = url.get_ref().clone();
    let kr = value.into_inner();

    // TODO:
    // if the attributes are from the same credential, put them in 1 discon (inner).
    // if the attributes are from different credentials, put them in seperate discons.
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

    let client = IrmaClientBuilder::new(&irma_url)
        .map_err(|_e| Error::Unexpected)?
        .build();

    let session = client
        .request(&dr)
        .await
        .or(Err(crate::Error::Unexpected))?;

    Ok(HttpResponse::Ok().json(session))
}
