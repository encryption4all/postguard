//! IRMA authentication and identity extraction middleware.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;

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

    Key(actix_web::web::Data<sqlx::PgPool>),

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

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
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
                Auth::Key(pool) => {
                    let auth = req.extract::<BearerAuth>().await?;
                    let api_key = auth.token();

                    if api_key.is_empty() {
                        return Err(crate::Error::Unexpected.into());
                    }

                    // Query database for API key using runtime query
                    let result = sqlx::query_as::<_, (String, serde_json::Value)>(
                        r#"
                        SELECT email, attributes
                        FROM api_keys
                        WHERE key = $1 AND expires_at > NOW()
                        "#,
                    )
                    .bind(api_key)
                    .fetch_optional(pool.as_ref())
                    .await
                    .map_err(|_| crate::Error::Unexpected)?;

                    let key_data = result.ok_or(crate::Error::DecodingError)?;

                    // Convert stored attributes to Vec<Attribute>
                    let attributes: Vec<Attribute> =
                        serde_json::from_value(key_data.1).unwrap_or_default();

                    SessionResult {
                        token: SessionToken(api_key.to_string()),
                        sessiontype: SessionType::Disclosing,
                        status: SessionStatus::Done,
                        proof_status: Some(ProofStatus::Valid),
                        disclosed: vec![attributes
                            .into_iter()
                            .map(|a| DisclosedAttribute {
                                raw_value: a.value,
                                identifier: a.atype.parse().unwrap_or_default(),
                                status: AttributeStatus::Present,
                                value: None,
                            })
                            .collect()],
                        signature: None,
                    }
                }
                Auth::Jwt(decoding_key) => {
                    let auth = req.extract::<BearerAuth>().await?;
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
    /// Authenticate using an API key contained in the database
    ///
    /// This method will simply check for the presence of a valid API key and get any metadata from
    /// the database, such as the associated email.
    Key,
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
    db_pool: Option<actix_web::web::Data<sqlx::PgPool>>, // Add optional pool
}

impl IrmaAuth {
    /// Create IRMA authentication middleware used to wrap a key service.
    ///
    /// See [`IrmaAuthType`] for the available methods.
    pub fn new(irma_url: String, method: IrmaAuthType) -> Self {
        Self { irma_url, method, db_pool: None }
    }

    pub fn with_db_pool(mut self, pool: actix_web::web::Data<sqlx::PgPool>) -> Self {
        self.db_pool = Some(pool);
        self
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
        let db_pool = self.db_pool.clone();

        async move {
            let auth_data = match auth_type {
                IrmaAuthType::Jwt => {
                    let jwt_pk_bytes = reqwest::get(&format!("{url}/publickey"))
                        .await
                        .map_err(|e| {
                            log::error!("Failed to retrieve JWT public key from {url}/publickey: {e}");
                        })?
                        .bytes()
                        .await
                        .map_err(|e| {
                            log::error!("Failed to read JWT public key bytes: {e}");
                        })?;
                    
                    let decoding_key = DecodingKey::from_rsa_pem(&jwt_pk_bytes)
                        .map_err(|e| {
                            log::error!(
                                "Failed to parse JWT public key as RSA PEM: {e}. \
                                Received {} bytes from {url}/publickey. \
                                Content preview: {:?}",
                                jwt_pk_bytes.len(),
                                String::from_utf8_lossy(&jwt_pk_bytes[..jwt_pk_bytes.len().min(200)])
                            );
                        })?;

                    Auth::Jwt(decoding_key)
                }
                IrmaAuthType::Key => {
                    let pool = db_pool.ok_or_else(|| {
                        log::error!("Database pool required for Key auth but not configured");
                    })?;
                    Auth::Key(pool)
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
