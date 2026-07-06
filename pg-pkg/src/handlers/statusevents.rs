use crate::util::{is_valid_session_token, IrmaUrl};
use actix_web::http::header;
use actix_web::{web::Data, HttpRequest, HttpResponse};

/// Proxies the IRMA server's Server-Sent Events status endpoint.
///
/// `GET /v2/{irma|request}/statusevents/{token}` forwards to the IRMA
/// server's `/session/{token}/statusevents`, streaming the `text/event-stream`
/// response straight back to the client. This lets `yivi-client` use
/// `serverSentEvents: true` (instant session-status updates over one
/// persistent connection) instead of polling every 500ms.
///
/// The `token` is the requestor session token, identical to the one used by
/// the [`jwt`](super::jwt) handler for `/session/{token}/result-jwt`. No
/// authentication is required: the endpoint only relays session-status events,
/// which carry no key material.
pub async fn statusevents(
    irma: Data<IrmaUrl>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::Error> {
    let token = req.match_info().query("token");

    // The token is interpolated into the upstream IRMA URL, so reject anything
    // that is not a well-formed session token before constructing the request.
    if !is_valid_session_token(token) {
        return Err(crate::Error::SessionTokenInvalid);
    }

    let irma_url = irma.get_ref().0.clone();

    let upstream = reqwest::get(&format!("{irma_url}/session/{token}/statusevents"))
        .await
        .or(Err(crate::Error::Unexpected))?
        .error_for_status()
        .or(Err(crate::Error::UpstreamError))?;

    // Stream the upstream SSE body back to the client without buffering, so
    // events are delivered as soon as the IRMA server emits them.
    let stream = upstream.bytes_stream();

    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/event-stream"))
        .insert_header((header::CACHE_CONTROL, "no-cache"))
        // Tell intermediary proxies (e.g. nginx) not to buffer the stream.
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawns a one-shot fake IRMA server that answers the next connection with
    /// a small `text/event-stream` body and then closes the connection (which
    /// ends the SSE stream). Returns the base URL to point `IrmaUrl` at.
    async fn spawn_fake_irma_sse(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Drain the request headers (read until the blank line) so the
            // client's GET is fully consumed before we reply.
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        });

        format!("http://{addr}")
    }

    /// Spawns a one-shot fake IRMA server that answers the next connection with
    /// the given HTTP error status line (e.g. `503 Service Unavailable`) and an
    /// empty body. Used to exercise the `error_for_status()` -> `UpstreamError`
    /// path. Returns the base URL to point `IrmaUrl` at.
    async fn spawn_fake_irma_error(status_line: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();

            let response = format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\n\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        });

        format!("http://{addr}")
    }

    #[actix_web::test]
    async fn statusevents_proxies_sse_body_and_content_type() {
        let body = "event: status\ndata: \"DONE\"\n\n";
        let irma_url = spawn_fake_irma_sse(body).await;

        let app = test::init_service(
            App::new().service(
                web::resource("/v2/irma/statusevents/{token}")
                    .app_data(Data::new(IrmaUrl(irma_url)))
                    .route(web::get().to(statusevents)),
            ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/irma/statusevents/ELMExi5iauWYHzbH7gwU")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache"
        );

        let received = test::read_body(resp).await;
        assert_eq!(received, body.as_bytes());
    }

    #[actix_web::test]
    async fn statusevents_maps_connection_failure_to_500() {
        // No upstream listening on this port → connection refused → the request
        // future errors before a response, surfacing as `Error::Unexpected` (500).
        let app = test::init_service(
            App::new().service(
                web::resource("/v2/irma/statusevents/{token}")
                    .app_data(Data::new(IrmaUrl("http://127.0.0.1:1".to_string())))
                    .route(web::get().to(statusevents)),
            ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/irma/statusevents/ELMExi5iauWYHzbH7gwU")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 500);
    }

    #[actix_web::test]
    async fn statusevents_maps_upstream_error_to_503() {
        // Upstream replies with an HTTP error status → `error_for_status()`
        // returns `Err` → `Error::UpstreamError`, which the PKG maps to 503.
        let irma_url = spawn_fake_irma_error("503 Service Unavailable").await;

        let app = test::init_service(
            App::new().service(
                web::resource("/v2/irma/statusevents/{token}")
                    .app_data(Data::new(IrmaUrl(irma_url)))
                    .route(web::get().to(statusevents)),
            ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/irma/statusevents/ELMExi5iauWYHzbH7gwU")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn statusevents_rejects_malformed_token_with_400() {
        // Point at an unroutable upstream: the handler must reject the token
        // *before* attempting any request, so no upstream is contacted.
        let app = test::init_service(
            App::new().service(
                web::resource("/v2/irma/statusevents/{token}")
                    .app_data(Data::new(IrmaUrl("http://127.0.0.1:1".to_string())))
                    .route(web::get().to(statusevents)),
            ),
        )
        .await;

        for token in [
            // A UUID is the wrong shape for an IRMA session token.
            "de305d54-75b4-431b-adb2-eb6b9e546013",
            // Too short.
            "ELMExi5iauWYHzbH7gw",
            // 20 chars but contains a URL metacharacter.
            "ELMExi5iauWYHzbH7gw.",
        ] {
            let req = test::TestRequest::get()
                .uri(&format!("/v2/irma/statusevents/{token}"))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 400, "expected 400 for token {token:?}");
        }
    }
}
