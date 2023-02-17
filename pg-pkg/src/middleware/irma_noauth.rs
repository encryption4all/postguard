//! Caution!
//! This middleware is for testing purposes only. The middleware performs no authentication and
//! simply extracts an identity from a IRMA policy contained in the request. The identity is passed
//! to the key service using the request extensions.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::Json,
    Error, HttpMessage,
};

use futures::future::{ready, Ready};
use futures::FutureExt;
use futures_util::future::LocalBoxFuture;
use std::rc::Rc;

use crate::middleware::irma::IrmaAuthResult;
use irma::ProofStatus;
use pg_core::identity::Policy;

#[doc(hidden)]
pub struct NoAuthService<S> {
    service: Rc<S>,
}

impl<S> Service<ServiceRequest> for NoAuthService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();

        async move {
            // Retrieve the policy from the request.
            let pol = req.extract::<Json<Policy>>().await?.into_inner();

            // Pass the result to the key service, which expects it in the extensions.
            req.extensions_mut().insert(IrmaAuthResult {
                con: pol.con,
                status: irma::SessionStatus::Done,
                proof_status: Some(ProofStatus::Valid),
                exp: None,
            });

            // Invoke the (wrapped) key service.
            let res = srv.call(req).await?;

            Ok(res)
        }
        .boxed_local()
    }
}

pub struct NoAuth;

impl NoAuth {
    pub fn new() -> Self {
        NoAuth {}
    }
}

impl<S> Transform<S, ServiceRequest> for NoAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type Transform = NoAuthService<S>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(NoAuthService {
            service: Rc::new(service),
        }))
    }
}
