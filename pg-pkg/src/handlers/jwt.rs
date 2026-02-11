use crate::util::IrmaUrl;
use actix_web::http::header::ContentType;
use actix_web::HttpRequest;
use actix_web::{web::Data, HttpResponse};

pub async fn jwt(irma: Data<IrmaUrl>, req: HttpRequest) -> Result<HttpResponse, crate::Error> {
    let token = req.match_info().query("token");
    let irma_url = irma.get_ref().0.clone();

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
