use crate::server::POSTGUARD_CLIENTS;
use crate::util::*;
use actix_http::header::HeaderValue;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse},
};
use futures::Future;

pub(crate) fn collect_metrics<
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
>(
    req: ServiceRequest,
    srv: &S,
) -> impl Future<Output = Result<ServiceResponse<B>, actix_web::Error>> {
    if let Some(Ok(header)) = req.headers().get(PG_CLIENT_HEADER).map(HeaderValue::to_str) {
        let split: Vec<_> = req.path().split('/').take(4).collect();
        let new_path = split.join("/");
        if let [host, host_version, app, app_version] = header.split(',').collect::<Vec<&str>>()[..]
        {
            POSTGUARD_CLIENTS
                .with_label_values(&[&new_path, host, host_version, app, app_version])
                .inc()
        }
    }

    srv.call(req)
}
