//! Authentication and identity extraction middleware.

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
pub(crate) struct AuthResult {
    pub con: Vec<Attribute>,
    pub status: SessionStatus,
    pub proof_status: Option<ProofStatus>,
    pub exp: Option<u64>,
}

/// Result of an API key lookup.
#[derive(Debug, Clone)]
pub struct ApiKeyData {
    pub email: String,
    pub attributes: Vec<Attribute>, // TODO: make attributes for api key less hacky. issue: #45
}

/// Trait for API key storage/lookup. Implement this trait to provide custom API key validation.
/// This abstraction allows for easy testing by providing mock implementations.
#[async_trait::async_trait(?Send)]
pub trait ApiKeyStore {
    /// Look up an API key and return the associated data if valid.
    /// Returns `None` if the key is not found or expired.
    async fn lookup(&self, api_key: &str) -> Result<Option<ApiKeyData>, crate::Error>;
}

/// PostgreSQL-backed API key store for production use.
#[derive(Clone)]
pub struct PgApiKeyStore {
    pool: sqlx::PgPool,
}

impl PgApiKeyStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait(?Send)]
impl ApiKeyStore for PgApiKeyStore {
    async fn lookup(&self, api_key: &str) -> Result<Option<ApiKeyData>, crate::Error> {
        let result = sqlx::query_as::<_, (String, serde_json::Value)>(
            r#"
            SELECT email, attributes
            FROM api_keys
            WHERE key = $1 AND expires_at > NOW()
            "#,
        )
        .bind(api_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| crate::Error::Unexpected)?;

        match result {
            Some((email, attrs_json)) => {
                let attributes: Vec<Attribute> =
                    serde_json::from_value(attrs_json).unwrap_or_default();
                Ok(Some(ApiKeyData { email, attributes }))
            }
            None => Ok(None),
        }
    }
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
enum AuthMethods {
    // Check the ongoing session using a token from the request.
    Token(String),

    // Check API key using an ApiKeyStore implementation.
    Key(Rc<dyn ApiKeyStore>),

    // Check the session by decoding a JWT from the request.
    Jwt(DecodingKey),
}

#[doc(hidden)]
pub struct AuthService<S> {
    service: Rc<S>,
    auth_data: Rc<AuthMethods>,
}

impl<S> Service<ServiceRequest> for AuthService<S>
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
                AuthMethods::Token(url) => {
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
                AuthMethods::Key(store) => {
                    let auth = req.extract::<BearerAuth>().await?;
                    let api_key = auth.token();

                    if api_key.is_empty() {
                        return Err(crate::Error::Unexpected.into());
                    }

                    let key_data = store
                        .lookup(api_key)
                        .await?
                        .ok_or(crate::Error::APIKeyInvalid)?;

                    let disclosed_attributes: Vec<DisclosedAttribute> = key_data
                        .attributes
                        .into_iter()
                        .map(|a| {
                            let identifier =
                                a.atype.parse().map_err(|_| crate::Error::DecodingError)?;
                            Ok(DisclosedAttribute {
                                raw_value: a.value,
                                identifier,
                                status: AttributeStatus::Present,
                                value: None,
                            })
                        })
                        .collect::<Result<_, crate::Error>>()?;

                    SessionResult {
                        token: SessionToken(api_key.to_string()),
                        sessiontype: SessionType::Disclosing,
                        status: SessionStatus::Done,
                        proof_status: Some(ProofStatus::Valid),
                        disclosed: vec![disclosed_attributes],
                        signature: None,
                    }
                }
                AuthMethods::Jwt(decoding_key) => {
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

            req.extensions_mut().insert(AuthResult {
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
/// Authentication type.
pub enum AuthType {
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

/// Authentication middleware.
#[derive(Clone)]
pub struct Auth {
    /// The URL to the IRMA server.
    irma_url: String,
    /// The authentication method.
    method: AuthType,
    /// Optional API key store for Key auth method.
    api_key_store: Option<Rc<dyn ApiKeyStore>>,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("irma_url", &self.irma_url)
            .field("method", &self.method)
            .field("api_key_store", &self.api_key_store.as_ref().map(|_| "..."))
            .finish()
    }
}

impl Auth {
    /// Create authentication middleware used to wrap a key service.
    ///
    /// See [`AuthType`] for the available methods.
    pub fn new(irma_url: String, method: AuthType) -> Self {
        Self {
            irma_url,
            method,
            api_key_store: None,
        }
    }

    /// Set the API key store for Key authentication.
    /// Use `PgApiKeyStore` for production or provide a custom implementation for testing.
    pub fn with_api_key_store<S: ApiKeyStore + 'static>(mut self, store: S) -> Self {
        self.api_key_store = Some(Rc::new(store));
        self
    }

    /// Convenience method to set up with a PostgreSQL pool.
    pub fn with_db_pool(self, pool: sqlx::PgPool) -> Self {
        self.with_api_key_store(PgApiKeyStore::new(pool))
    }
}

impl<S> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Transform, Self::InitError>>;
    type Transform = AuthService<S>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Self::Future {
        let url = self.irma_url.clone();
        let auth_type = self.method.clone();
        let api_key_store = self.api_key_store.clone();

        async move {
            let auth_data = match auth_type {
                AuthType::Jwt => {
                    let jwt_pk_bytes = reqwest::get(&format!("{url}/publickey"))
                        .await
                        .map_err(|e| {
                            log::error!(
                                "Failed to retrieve JWT public key from {url}/publickey: {e}"
                            );
                        })?
                        .bytes()
                        .await
                        .map_err(|e| {
                            log::error!("Failed to read JWT public key bytes: {e}");
                        })?;

                    let decoding_key = DecodingKey::from_rsa_pem(&jwt_pk_bytes).map_err(|e| {
                        log::error!(
                            "Failed to parse JWT public key as RSA PEM: {e}. \
                                Received {} bytes from {url}/publickey. \
                                Content preview: {:?}",
                            jwt_pk_bytes.len(),
                            String::from_utf8_lossy(&jwt_pk_bytes[..jwt_pk_bytes.len().min(200)])
                        );
                    })?;

                    AuthMethods::Jwt(decoding_key)
                }
                AuthType::Key => {
                    let store = api_key_store.ok_or_else(|| {
                        log::error!("API key store required for Key auth but not configured");
                    })?;
                    AuthMethods::Key(store)
                }
                AuthType::Token => AuthMethods::Token(url),
            };

            Ok(AuthService {
                service: Rc::new(service),
                auth_data: Rc::new(auth_data),
            })
        }
        .boxed_local()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Mock API key store for testing purposes.
    /// Configure it with expected keys and their associated data.
    #[derive(Default, Clone)]
    pub struct MockApiKeyStore {
        keys: std::collections::HashMap<String, ApiKeyData>,
    }

    impl MockApiKeyStore {
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a valid API key with associated data.
        pub fn with_key(mut self, key: impl Into<String>, data: ApiKeyData) -> Self {
            self.keys.insert(key.into(), data);
            self
        }
    }

    #[async_trait::async_trait(?Send)]
    impl ApiKeyStore for MockApiKeyStore {
        async fn lookup(&self, api_key: &str) -> Result<Option<ApiKeyData>, crate::Error> {
            Ok(self.keys.get(api_key).cloned())
        }
    }

    #[actix_web::test]
    async fn test_mock_api_key_store_lookup_valid() {
        let store = MockApiKeyStore::new().with_key(
            "valid-key",
            ApiKeyData {
                email: "user@example.com".to_string(),
                attributes: vec![],
            },
        );

        let result = store.lookup("valid-key").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "user@example.com");
    }

    #[actix_web::test]
    async fn test_mock_api_key_store_lookup_invalid() {
        let store = MockApiKeyStore::new();

        let result = store.lookup("nonexistent-key").await.unwrap();
        assert!(result.is_none());
    }
}
