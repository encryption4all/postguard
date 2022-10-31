//! Caution!
//! This middleware is for testing purposes only. The middleware performs no authentication and
//! simply extracts an identity from a IRMA policy contained in the request. The identity is passed
//! to the key service using the request extensions.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::Json,
    Error, HttpMessage, HttpResponse,
};

use futures::future::{ready, Ready};
use futures::FutureExt;
use futures_util::future::LocalBoxFuture;
use std::marker::PhantomData;
use std::rc::Rc;

use serde::Serialize;

use irma::{ProofStatus, SessionStatus};
use irmaseal_core::{api::KeyResponse, kem::IBKEM, Policy, UserSecretKey};

#[doc(hidden)]
pub struct NoAuthService<S, K> {
    service: Rc<S>,
    scheme: PhantomData<K>,
}

impl<S, K> Service<ServiceRequest> for NoAuthService<S, K>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    K: IBKEM + 'static,
    UserSecretKey<K>: Serialize,
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

            // Derive an id for this policy.
            let id = pol.derive::<K>().map_err(|_e| crate::Error::Unexpected)?;

            // Pass the derived id to the key service, which expects it in the extensions.
            req.extensions_mut().insert(id);

            // Invoke the (wrapped) key service.
            let res = srv.call(req).await?;

            // Retrieve the (if present) key from the response extensions.
            let usk = res
                .response()
                .extensions()
                .get::<K::Usk>()
                .cloned()
                .map(UserSecretKey);

            // Create a new response, including the key.
            let new_req = res.request().clone();
            let new_res = HttpResponse::Ok().json(KeyResponse {
                status: SessionStatus::Done,
                proof_status: Some(ProofStatus::Valid),
                key: usk,
            });

            Ok(ServiceResponse::new(new_req, new_res))
        }
        .boxed_local()
    }
}

pub struct NoAuth<K>(PhantomData<K>);

impl<K> NoAuth<K> {
    pub fn new() -> Self {
        NoAuth(PhantomData)
    }
}

impl<S, K> Transform<S, ServiceRequest> for NoAuth<K>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    K: IBKEM + 'static,
    UserSecretKey<K>: Serialize,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type Transform = NoAuthService<S, K>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(NoAuthService {
            service: Rc::new(service),
            scheme: PhantomData,
        }))
    }
}
