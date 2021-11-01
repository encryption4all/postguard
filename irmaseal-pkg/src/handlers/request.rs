use actix_web::web::{Data, HttpResponse, Json};
use irmaseal_core::api::KeyRequest;

use irma::*;

pub async fn request(
    url: Data<String>,
    value: Json<KeyRequest>,
) -> Result<HttpResponse, crate::Error> {
    let irma_url = url.get_ref().clone();
    let kr = value.into_inner();

    let dr = DisclosureRequestBuilder::new()
        .add_discon(vec![vec![kr.attribute]])
        .build();

    let client = IrmaClientBuilder::new(&irma_url).unwrap().build();

    let session = client
        .request(&dr)
        .await
        .or(Err(crate::Error::Unexpected))?;

    Ok(HttpResponse::Ok().json(session))
}
