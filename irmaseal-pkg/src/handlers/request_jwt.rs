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
        .or(Err(crate::Error::Unexpected))?
        .error_for_status()
        .or(Err(crate::Error::UpstreamError))?
        .text()
        .await
        .or(Err(crate::Error::Unexpected))?;

    Ok(HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(jwt))
}
