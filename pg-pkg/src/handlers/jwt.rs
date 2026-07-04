use crate::util::{is_valid_uuid_v4, IrmaUrl};
use actix_web::http::header::ContentType;
use actix_web::HttpRequest;
use actix_web::{web::Data, HttpResponse};

pub async fn jwt(irma: Data<IrmaUrl>, req: HttpRequest) -> Result<HttpResponse, crate::Error> {
    let token = req.match_info().query("token");

    // The token is interpolated into the upstream IRMA URL, so reject anything
    // that is not a canonical UUID v4 before constructing the request.
    if !is_valid_uuid_v4(token) {
        return Err(crate::Error::SessionTokenInvalid);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn jwt_rejects_malformed_token_with_400() {
        // Point at an unroutable upstream: the handler must reject the token
        // *before* attempting any request, so no upstream is contacted.
        let app = test::init_service(
            App::new().service(
                web::resource("/v2/irma/jwt/{token}")
                    .app_data(Data::new(IrmaUrl("http://127.0.0.1:1".to_string())))
                    .route(web::get().to(jwt)),
            ),
        )
        .await;

        for token in [
            "not-a-uuid",
            "ge305d54-75b4-431b-adb2-eb6b9e546013",
            "de305d54-75b4-431b-adb2-eb6b9e54601",
        ] {
            let req = test::TestRequest::get()
                .uri(&format!("/v2/irma/jwt/{token}"))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 400, "expected 400 for token {token:?}");
        }
    }
}
