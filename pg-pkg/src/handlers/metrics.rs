use crate::Error;
use actix_web::HttpRequest;
use prometheus::{Encoder, TextEncoder};

pub async fn metrics(_req: HttpRequest) -> Result<String, Error> {
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(Error::Prometheus)?;

    String::from_utf8(buffer).map_err(|_e| Error::Unexpected)
}
