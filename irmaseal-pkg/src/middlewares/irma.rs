use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::extractors::AuthExtractor;

use futures::FutureExt;
use futures_util::future::LocalBoxFuture;
use std::{marker::PhantomData, rc::Rc};

use irma::*;
use irmaseal_core::{api::KeyResponse, kem::IBKEM, Attribute, Policy, UserSecretKey};

use jsonwebtoken::{decode, errors::ErrorKind, Algorithm, DecodingKey, Validation};

use serde::{Deserialize, Serialize};

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

/// IRMA authentication and id extraction middleware.

#[derive(Clone)]
enum Auth {
    // Check the ongoing session at {irma_url}/session/{token} associated with this token.
    Token(String),

    // Retrieve JWT decoding key from irma_url and retrieve the session result by checking the JWT in the request.
    Jwt(DecodingKey),
}

#[doc(hidden)]
pub struct IrmaAuthService<S, K> {
    service: Rc<S>,
    auth_data: Rc<Auth>,
    scheme: PhantomData<K>,
}

impl<S, K> Service<ServiceRequest> for IrmaAuthService<S, K>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    K: IBKEM + 'static,
    UserSecretKey<K>: Serialize,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let auth = self.auth_data.clone();

        async move {
            let timestamp = req
                .match_info()
                .query("timestamp")
                .parse::<u64>()
                .map_err(|_e| crate::Error::Unexpected)?;

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

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_e| crate::Error::Unexpected)?
                        .as_secs();

                    // It is not allowed to ask for USKs with a timestamp in the future.
                    if timestamp > now {
                        return Err(crate::Error::ChronologyError.into());
                    }

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

                    // It is not allowed to ask for USKs with a timestamp beyond the expiry date.
                    if timestamp > decoded.claims.exp {
                        return Err(crate::Error::ChronologyError.into());
                    }

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

            // Validate the session result. Filter attributes that were not present.
            let validated = match session_result {
                SessionResult {
                    status: SessionStatus::Done,
                    proof_status: Some(ProofStatus::Valid),
                    sessiontype: SessionType::Disclosing,
                    ref disclosed,
                    ..
                } => Some(
                    disclosed
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
                ),
                _ => None,
            }
            .ok_or(crate::Error::SessionError)?;

            let policy = Policy {
                timestamp,
                con: validated,
            };

            let id = policy
                .derive::<K>()
                .map_err(|_e| crate::Error::Unexpected)?;

            // Pass the derived id to the key service.
            req.extensions_mut().insert(id);

            // Invoke the (wrapped) key service.
            let res = srv.call(req).await?;

            // Retrieve the (if present) key from the response extensions.
            let usk = res
                .response()
                .extensions()
                .get::<UserSecretKey<K>>()
                .cloned();

            let new_req = res.request().clone();
            let new_res = HttpResponse::Ok().json(KeyResponse {
                status: session_result.status,
                proof_status: session_result.proof_status,
                key: usk,
            });

            Ok(ServiceResponse::new(new_req, new_res))
        }
        .boxed_local()
    }
}

// Factory for the IRMA middleware.

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum IrmaAuthType {
    /// Authenticate using IRMA session tokens.
    Token,
    /// Authenticate using IRMA signed session results (JWTs).
    Jwt,
}

/// IRMA Authentication option.
#[derive(Debug, Clone)]
pub struct IrmaAuth<K> {
    /// The URL to the IRMA server.
    irma_url: String,
    /// The authentication method.
    method: IrmaAuthType,
    scheme: PhantomData<K>,
}

impl<K: IBKEM> IrmaAuth<K> {
    pub fn new(irma_url: String, method: IrmaAuthType) -> Self {
        Self {
            irma_url,
            method,
            scheme: PhantomData,
        }
    }
}

impl<S, K> Transform<S, ServiceRequest> for IrmaAuth<K>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    K: IBKEM + 'static,
    UserSecretKey<K>: Serialize,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Transform, Self::InitError>>;
    type Transform = IrmaAuthService<S, K>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Self::Future {
        let url = self.irma_url.clone();
        let auth_type = self.method.clone();

        async move {
            let auth_data = match auth_type {
                IrmaAuthType::Jwt => {
                    let jwt_pk_bytes = reqwest::get(&format!("{}/publickey", url))
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
                scheme: PhantomData,
            })
        }
        .boxed_local()
    }
}
