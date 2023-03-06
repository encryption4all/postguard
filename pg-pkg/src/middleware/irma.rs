//! IRMA authentication and identity extraction middleware.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::extractors::AuthExtractor;

use futures::FutureExt;
use futures_util::future::LocalBoxFuture;
use std::rc::Rc;

use irma::*;
use pg_core::identity::Attribute;

use jsonwebtoken::{decode, errors::ErrorKind, Algorithm, DecodingKey, Validation};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub(crate) struct IrmaAuthResult {
    pub con: Vec<Attribute>,
    pub status: SessionStatus,
    pub proof_status: Option<ProofStatus>,
    pub exp: Option<u64>,
}

/// Custom claims signed by the IRMA server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claims {
    // Mandatory JWT fields.
    exp: u64,
    iat: u64,
    iss: String,
    sub: String,

    // Mandatory IRMA claims, always present.
    token: irma::SessionToken,
    status: irma::SessionStatus,
    r#type: irma::SessionType,

    // Optional fields, only present when the session is a finished disclosure session.
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_status: Option<irma::ProofStatus>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    disclosed: Vec<Vec<DisclosedAttribute>>,
}

#[derive(Clone)]
enum Auth {
    // Check the ongoing session using a token from the request.
    Token(String),

    // Check the session by decoding a JWT from the request.
    Jwt(DecodingKey),
}

#[doc(hidden)]
pub struct IrmaAuthService<S> {
    service: Rc<S>,
    auth_data: Rc<Auth>,
}

impl<S> Service<ServiceRequest> for IrmaAuthService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let auth = self.auth_data.clone();

        async move {
            let mut exp = None;

            let session_result = match &*auth {
                Auth::Token(url) => {
                    let token_str = req.match_info().query("token");

                    if token_str.is_empty() {
                        return Err(crate::Error::Unexpected.into());
                    }

                    let token = SessionToken(token_str.to_string());

                    let res = IrmaClientBuilder::new(url)
                        .map_err(|_e| crate::Error::Unexpected)?
                        .build()
                        .result(&token)
                        .await
                        .map_err(|_e| crate::Error::Unexpected)?;

                    res
                }
                Auth::Jwt(decoding_key) => {
                    let auth = BearerAuth::from_service_request(&req).await?;
                    let jwt = auth.token();

                    let mut validation = Validation::new(Algorithm::RS256);
                    validation.leeway = 0;

                    let decoded =
                        decode::<Claims>(jwt, decoding_key, &validation).map_err(|e| {
                            match e.into_kind() {
                                ErrorKind::ExpiredSignature => crate::Error::ChronologyError,
                                _ => crate::Error::DecodingError,
                            }
                        })?;

                    exp = Some(decoded.claims.exp);

                    SessionResult {
                        token: decoded.claims.token,
                        sessiontype: decoded.claims.r#type,
                        status: decoded.claims.status,
                        proof_status: decoded.claims.proof_status,
                        disclosed: decoded.claims.disclosed,
                        signature: None,
                    }
                }
            };

            // Validate the session result. Purge attributes that were not present.
            let validated: Vec<Attribute> = match session_result {
                SessionResult {
                    status: SessionStatus::Done,
                    proof_status: Some(ProofStatus::Valid),
                    sessiontype: SessionType::Disclosing,
                    ref disclosed,
                    ..
                } => disclosed
                    .iter()
                    .flatten()
                    .filter_map(|att| match att {
                        DisclosedAttribute {
                            raw_value: val,
                            identifier,
                            status: AttributeStatus::Present,
                            ..
                        } => Some(Attribute {
                            atype: identifier.to_string(),
                            value: val.clone(),
                        }),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            };

            req.extensions_mut().insert(IrmaAuthResult {
                con: validated,
                exp,
                status: session_result.status,
                proof_status: session_result.proof_status,
            });

            let res = srv.call(req).await?;

            Ok(res)
        }
        .boxed_local()
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
/// IRMA authentication type.
pub enum IrmaAuthType {
    /// Authenticate using IRMA session tokens.
    ///
    /// This method will retrieve the session results from the IRMA server using the supplied
    /// token.
    Token,
    /// Authenticate using IRMA signed session results (JWTs).
    ///
    /// This method will try to retrieve the public key to verify JWTs from the URL.
    /// If no public key can be retrieved, setup of the middleware will panic.
    Jwt,
}

/// IRMA Authentication middleware.
#[derive(Debug, Clone)]
pub struct IrmaAuth {
    /// The URL to the IRMA server.
    irma_url: String,
    /// The authentication method.
    method: IrmaAuthType,
}

impl IrmaAuth {
    /// Create IRMA authentication middleware used to wrap a key service.
    ///
    /// See [`IrmaAuthType`] for the available methods.
    pub fn new(irma_url: String, method: IrmaAuthType) -> Self {
        Self { irma_url, method }
    }
}

impl<S> Transform<S, ServiceRequest> for IrmaAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Transform, Self::InitError>>;
    type Transform = IrmaAuthService<S>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Self::Future {
        let url = self.irma_url.clone();
        let auth_type = self.method.clone();

        async move {
            let auth_data = match auth_type {
                IrmaAuthType::Jwt => {
                    let jwt_pk_bytes = reqwest::get(&format!("{url}/publickey"))
                        .await
                        .expect("could not retrieve JWT public key")
                        .bytes()
                        .await
                        .expect("could not retrieve JWT public key bytes");
                    let decoding_key = DecodingKey::from_rsa_pem(&jwt_pk_bytes)
                        .expect("could not parse JWT public key");

                    Auth::Jwt(decoding_key)
                }
                IrmaAuthType::Token => Auth::Token(url),
            };

            Ok(IrmaAuthService {
                service: Rc::new(service),
                auth_data: Rc::new(auth_data),
            })
        }
        .boxed_local()
    }
}
