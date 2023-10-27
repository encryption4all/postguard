use crate::server::POSTGUARD_CLIENTS;
use crate::util::*;
use actix_http::header::HeaderValue;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse},
};
use futures::Future;
use futures_util::future::FutureExt;

pub(crate) fn collect_metrics<
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
>(
    req: ServiceRequest,
    srv: &S,
) -> impl Future<Output = Result<ServiceResponse<B>, actix_web::Error>> {
    let mut values = None;

    if let Some(Ok(header)) = req.headers().get(PG_CLIENT_HEADER).map(HeaderValue::to_str) {
        if let Some(path) = req.match_pattern() {
            if let [host, host_version, app, app_version] =
                header.split(',').collect::<Vec<&str>>()[..]
            {
                values = Some([
                    path,
                    host.to_string(),
                    host_version.to_string(),
                    app.to_string(),
                    app_version.to_string(),
                ]);
            }
        }
    }

    srv.call(req).map(|res| {
        let status = match &res {
            Ok(resp) => resp.status(),
            Err(e) => e.as_response_error().status_code(),
        };

        if let Some([a, b, c, d, e]) = values {
            POSTGUARD_CLIENTS
                .with_label_values(&[&a, &b, &c, &d, &e, status.as_str()])
                .inc();
        }

        res
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::server::tests::default_setup;
    use actix_http::header::HeaderName;
    use actix_http::StatusCode;
    use actix_web::test;
    use irma::SessionStatus;
    use pg_core::api::{KeyResponse, Parameters};
    use pg_core::artifacts::{PublicKey, UserSecretKey};
    use pg_core::identity::{Attribute, Policy};
    use pg_core::kem::cgw_kv::CGWKV;

    #[actix_web::test]
    async fn test_get_metrics() {
        let (app, pk, _, _, _) = default_setup().await;
        let header_name = HeaderName::from_str(PG_CLIENT_HEADER).unwrap();

        // First request
        let header = (
            header_name.clone(),
            HeaderValue::from_static("Outlook,1234.5678.90,pg4ol,0.0.1"),
        );
        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .insert_header(header)
            .to_request();
        let kr: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(&kr.public_key.0, &pk);

        // Second request
        let header = (
            header_name.clone(),
            HeaderValue::from_static("Thunderbird,1234.5678.90,pg4tb,0.0.2"),
        );
        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .insert_header(header)
            .to_request();
        let kr: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(&kr.public_key.0, &pk);

        // Third request (same as first)
        let header = (
            header_name.clone(),
            HeaderValue::from_static("Outlook,1234.5678.90,pg4ol,0.0.1"),
        );
        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .insert_header(header)
            .to_request();
        let kr: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(&kr.public_key.0, &pk);

        // Fourth request
        let header = (
            header_name,
            HeaderValue::from_static("Outlook,1234.5678.90,pg4ol,0.0.1"),
        );
        let ts = crate::server::tests::now();
        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };
        let req_usk = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .insert_header(header)
            .set_json(pol.clone())
            .to_request();
        let key_response: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req_usk).await;
        assert_eq!(key_response.status, SessionStatus::Done);

        // Collect metrics
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = test::read_body(res).await;

        let expected = "\
        # HELP postguard_clients Contains information about PostGuard clients connecting with the PKG.\n\
        # TYPE postguard_clients counter\n\
        postguard_clients{client=\"pg4ol\",client_version=\"0.0.1\",host=\"Outlook\",host_version=\"1234.5678.90\",path=\"/v2/key/{timestamp}\",status=\"200\"} 1\n\
        postguard_clients{client=\"pg4ol\",client_version=\"0.0.1\",host=\"Outlook\",host_version=\"1234.5678.90\",path=\"/v2/parameters\",status=\"200\"} 2\n\
        postguard_clients{client=\"pg4tb\",client_version=\"0.0.2\",host=\"Thunderbird\",host_version=\"1234.5678.90\",path=\"/v2/parameters\",status=\"200\"} 1\n";

        assert_eq!(actix_web::web::Bytes::from(expected), body);
    }
}
