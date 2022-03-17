use actix_web::http::header::ContentType;
use actix_web::{web::Data, web::Path, HttpResponse};

pub async fn request_jwt(
    irma: Data<String>,
    path: Path<String>,
) -> Result<HttpResponse, crate::Error> {
    let irma_url = irma.get_ref().clone();
    let token = path.into_inner();

    let jwt = reqwest::get(&format!("{irma_url}/session/{token}/result-jwt"))
        .await
        .map_err(|_e| crate::Error::Unexpected)?
        .text()
        .await
        .map_err(|_e| crate::Error::Unexpected)?;

    dbg!(&jwt);

    Ok(HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(jwt))
}
