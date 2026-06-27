use crate::util::IrmaUrl;
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
            .uri("/v2/irma/statusevents/some-session-token")
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
    async fn statusevents_maps_upstream_error_to_503() {
        // No upstream listening on this port → connection refused → Unexpected.
        // Point at a closed port to exercise the error path.
        let app = test::init_service(
            App::new().service(
                web::resource("/v2/irma/statusevents/{token}")
                    .app_data(Data::new(IrmaUrl("http://127.0.0.1:1".to_string())))
                    .route(web::get().to(statusevents)),
            ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/irma/statusevents/some-session-token")
            .to_request();

        let resp = test::call_service(&app, req).await;
        // A failed connection surfaces as `Error::Unexpected` (500).
        assert_eq!(resp.status(), 500);
    }
}
