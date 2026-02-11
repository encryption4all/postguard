use crate::Error;
use actix_web::HttpResponse;

pub async fn health() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/plain").body("OK"))
}
