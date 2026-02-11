//! Caution!
//! This middleware is for testing purposes only. The middleware performs no authentication and
//! simply extracts an identity from a IRMA policy contained in the request. The identity is passed
//! to the key service using the request extensions.

use actix_http::h1::Payload;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::{BytesMut, Json},
    Error, HttpMessage,
};

use futures::future::{ready, Ready};
use futures::FutureExt;
use futures_util::{future::LocalBoxFuture, StreamExt};
use std::rc::Rc;

use crate::middleware::auth::AuthResult;
use irma::ProofStatus;
use pg_core::{api::SigningKeyRequest, identity::Policy};

#[doc(hidden)]
pub struct NoAuthService<S> {
    service: Rc<S>,
    sort: Rc<NoAuth>,
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
        let sort = self.sort.clone();

        async move {
            // Retrieve the policy from the request.
            let pol = match &*sort {
                NoAuth::Decryption => req.extract::<Json<Policy>>().await?.into_inner(),
                NoAuth::Signing => {
                    let mut body = BytesMut::new();
                    let mut stream = req.take_payload();

                    while let Some(chunk) = stream.next().await {
                        body.extend_from_slice(&chunk?);
                    }

                    let skr = serde_json::from_slice::<SigningKeyRequest>(&body)?;

                    let (_, mut payload) = Payload::create(true);
                    payload.unread_data(body.into());
                    req.set_payload(payload.into());

                    let mut con = vec![];
                    con.extend(skr.pub_sign_id);
                    if let Some(priv_id) = skr.priv_sign_id {
                        con.extend(priv_id);
                    }

                    Policy { timestamp: 0, con }
                }
            };

            // Pass the result to the key service, which expects it in the extensions.
            req.extensions_mut().insert(AuthResult {
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

#[derive(Clone)]
pub enum NoAuth {
    Decryption,
    Signing,
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
            sort: Rc::new(self.clone()),
        }))
    }
}
