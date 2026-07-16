//! Authentication and identity extraction middleware.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;

use futures::FutureExt;
use futures_util::future::LocalBoxFuture;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

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

/// Result of an API key lookup. Values populated from the `organizations` row
/// referenced by the matched `business_api_keys` entry on the postguard-business
/// database. Which attributes are actually signed is controlled by
/// `signing_attrs` — see [`PgApiKeyStore::lookup`].
#[derive(Debug, Clone)]
pub struct ApiKeyData {
    /// Stable tenant identifier — `organizations.id` (uuid, stringified).
    /// Used by callers like cryptify as the per-tenant accounting key for
    /// quotas. Not exposed in any signing identity.
    pub org_id: String,
    pub email: String,
    pub organisation_name: Option<String>,
    pub phone_number: Option<String>,
    pub kvk_number: Option<String>,
    pub organisation_name_public: bool,
    pub phone_number_public: bool,
    pub kvk_number_public: bool,
}

/// Pub/priv attribute split determined by the API key's database configuration.
/// When present in request extensions, the signing_key handler uses this
/// instead of the client-provided SigningKeyRequest body.
#[derive(Debug, Clone)]
pub(crate) struct ApiKeySigningInfo {
    pub pub_attributes: Vec<Attribute>,
    pub priv_attributes: Vec<Attribute>,
}

/// Trait for API key storage/lookup. Implement this trait to provide custom API key validation.
/// This abstraction allows for easy testing by providing mock implementations.
#[async_trait::async_trait(?Send)]
pub trait ApiKeyStore {
    /// Look up an API key and return the associated data if valid.
    /// Returns `None` if the key is not found or expired.
    async fn lookup(&self, api_key: &str) -> Result<Option<ApiKeyData>, crate::Error>;
}

/// PostgreSQL-backed API key store that reads from the postguard-business
/// schema (`business_api_keys` JOIN `organizations`).
///
/// Raw `PG-<base64url>` keys issued by the business portal are SHA-256 hashed
/// on the business side; the raw key is never stored. This store takes the raw
/// key from the Authorization header, hashes it, and looks up the hash.
///
/// The per-attribute `signing_attrs` JSONB configured in the business portal
/// determines which organisation attributes are disclosed in the signing
/// identity. `signing_attrs: true` → attribute is included as public;
/// `signing_attrs: false` → attribute is omitted. The public/private split
/// that existed in the legacy pg-pkg `api_keys` schema is not currently
/// expressible in the business schema — see PR discussion on issue #140.
#[derive(Clone)]
pub struct PgApiKeyStore {
    pool: sqlx::PgPool,
}

impl PgApiKeyStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

#[async_trait::async_trait(?Send)]
impl ApiKeyStore for PgApiKeyStore {
    async fn lookup(&self, api_key: &str) -> Result<Option<ApiKeyData>, crate::Error> {
        let key_hash = sha256_hex(api_key);

        let result = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                serde_json::Value,
            ),
        >(
            r#"
            SELECT o.id::text, o.signing_email, o.name, u.phone, o.kvk_number, k.signing_attrs
            FROM business_api_keys k
            JOIN organizations o ON o.id = k.org_id
            LEFT JOIN users u ON u.id = o.contact_user_id
            WHERE k.key_hash = $1
              AND k.expires_at > NOW()
              AND k.revoked_at IS NULL
            "#,
        )
        .bind(&key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!("business_api_keys lookup failed: {e}");
            crate::Error::Unexpected
        })?;

        let Some((org_id, org_email, org_name, org_phone, org_kvk, signing_attrs)) = result else {
            return Ok(None);
        };

        // Best-effort touch of last_used_at. Failures here must not prevent
        // the request from succeeding.
        if let Err(e) =
            sqlx::query("UPDATE business_api_keys SET last_used_at = NOW() WHERE key_hash = $1")
                .bind(&key_hash)
                .execute(&self.pool)
                .await
        {
            log::warn!("failed to update business_api_keys.last_used_at: {e}");
        }

        let flag = |k: &str| -> bool {
            signing_attrs
                .get(k)
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        // signing_attrs:true → include as public; signing_attrs:false → omit.
        // If the business portal turns off `email` the signing identity simply
        // won't include it; the portal UI enforces "at least one attribute
        // selected" so we do not enforce that again here.
        let email = if flag("email") {
            org_email
        } else {
            String::new()
        };
        let organisation_name = if flag("orgName") && !org_name.is_empty() {
            Some(org_name)
        } else {
            None
        };
        let phone_number = org_phone.filter(|v| !v.is_empty() && flag("phone"));
        let kvk_number = org_kvk.filter(|v| !v.is_empty() && flag("kvkNumber"));

        // The business schema has no public/private split — every enabled
        // attribute is published in the signing identity.
        Ok(Some(ApiKeyData {
            org_id,
            email,
            organisation_name,
            phone_number,
            kvk_number,
            organisation_name_public: true,
            phone_number_public: true,
            kvk_number_public: true,
        }))
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

/// Lazily-fetched cache of the IRMA server's JWT verification key.
///
/// The key is fetched on first use instead of during worker startup, so the
/// PKG no longer exits (or hangs) when the IRMA server is briefly unreachable
/// at boot; JWT requests degrade to 503 until the IRMA server is back.
pub(crate) struct JwtKeyCache {
    /// `{irma_url}/publickey`
    url: String,
    /// Workers are single-threaded (services are `Rc`-shared), so `RefCell`
    /// suffices. Borrows are never held across an await point.
    key: RefCell<Option<DecodingKey>>,
}

impl JwtKeyCache {
    fn new(irma_url: &str) -> Self {
        Self {
            url: format!("{irma_url}/publickey"),
            key: RefCell::new(None),
        }
    }

    /// Fetch and parse the verification key from the IRMA server.
    async fn fetch(&self) -> Result<DecodingKey, crate::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_e| crate::Error::Unexpected)?;

        let bytes = client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| {
                log::error!("Failed to retrieve JWT public key from {}: {e}", self.url);
                crate::Error::UpstreamError
            })?
            .bytes()
            .await
            .map_err(|e| {
                log::error!("Failed to read JWT public key bytes: {e}");
                crate::Error::UpstreamError
            })?;

        DecodingKey::from_rsa_pem(&bytes).map_err(|e| {
            log::error!(
                "Failed to parse JWT public key as RSA PEM: {e}. \
                    Received {} bytes from {}. \
                    Content preview: {:?}",
                bytes.len(),
                self.url,
                String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
            );
            crate::Error::UpstreamError
        })
    }

    /// Decode and validate a JWT, fetching the verification key on first use.
    async fn decode(&self, jwt: &str) -> Result<Claims, crate::Error> {
        if self.key.borrow().is_none() {
            let key = self.fetch().await?;
            *self.key.borrow_mut() = Some(key);
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 0;

        let borrowed = self.key.borrow();
        // Populated above if it was empty.
        let key = borrowed.as_ref().ok_or(crate::Error::Unexpected)?;

        decode::<Claims>(jwt, key, &validation)
            .map(|decoded| decoded.claims)
            .map_err(|e| match e.into_kind() {
                ErrorKind::ExpiredSignature => crate::Error::ChronologyError,
                _ => crate::Error::DecodingError,
            })
    }
}

#[derive(Clone)]
enum AuthMethods {
    // Check the ongoing session using a token from the request.
    Token(String),

    // Check API key using an ApiKeyStore implementation.
    Key(Rc<dyn ApiKeyStore>),

    // Check the session by decoding a JWT from the request, verified against
    // the IRMA server's (lazily fetched) public key.
    Jwt(Rc<JwtKeyCache>),
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

                    // Build pub/priv attribute lists from the structured fields.
                    // Email is only included when the business portal enabled
                    // `signing_attrs.email`; an empty string signals disabled.
                    let mut pub_attrs: Vec<Attribute> = Vec::new();
                    if !key_data.email.is_empty() {
                        pub_attrs.push(Attribute::new(
                            "pbdf.sidn-pbdf.email.email",
                            Some(&key_data.email),
                        ));
                    }
                    let mut priv_attrs: Vec<Attribute> = Vec::new();

                    let optional_fields: &[(Option<&str>, bool, &str)] = &[
                        (
                            key_data.organisation_name.as_deref(),
                            key_data.organisation_name_public,
                            "pbdf.pbdf.kvk.displayName",
                        ),
                        (
                            key_data.phone_number.as_deref(),
                            key_data.phone_number_public,
                            "pbdf.sidn-pbdf.mobilenumber.mobilenumber",
                        ),
                        (
                            key_data.kvk_number.as_deref(),
                            key_data.kvk_number_public,
                            "pbdf.pbdf.kvk.kvkNumber",
                        ),
                    ];

                    for (value, is_public, attr_type) in optional_fields {
                        if let Some(val) = value {
                            let attr = Attribute::new(attr_type, Some(val));
                            if *is_public {
                                pub_attrs.push(attr);
                            } else {
                                priv_attrs.push(attr);
                            }
                        }
                    }

                    // Store the pub/priv split for the signing_key handler.
                    req.extensions_mut().insert(ApiKeySigningInfo {
                        pub_attributes: pub_attrs.clone(),
                        priv_attributes: priv_attrs.clone(),
                    });

                    // Expose the validated key data to handlers that just need
                    // identity (e.g. the `/v2/api-key/validate` endpoint) without
                    // running through signing-key issuance.
                    req.extensions_mut().insert(key_data.clone());

                    // Build all attributes as disclosed for the session result.
                    let all_attrs: Vec<Attribute> =
                        pub_attrs.into_iter().chain(priv_attrs).collect();

                    let disclosed_attributes: Vec<DisclosedAttribute> = all_attrs
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
                AuthMethods::Jwt(key_cache) => {
                    let auth = req.extract::<BearerAuth>().await?;
                    let jwt = auth.token();

                    let claims = key_cache.decode(jwt).await?;

                    exp = Some(claims.exp);

                    SessionResult {
                        token: claims.token,
                        sessiontype: claims.r#type,
                        status: claims.status,
                        proof_status: claims.proof_status,
                        disclosed: claims.disclosed,
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
                // No network I/O here: the verification key is fetched lazily
                // on the first JWT request (see `JwtKeyCache`), so worker
                // startup neither fails nor blocks when the IRMA server is
                // unreachable.
                AuthType::Jwt => AuthMethods::Jwt(Rc::new(JwtKeyCache::new(&url))),
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
                org_id: "00000000-0000-0000-0000-000000000001".to_string(),
                email: "user@example.com".to_string(),
                organisation_name: None,
                phone_number: None,
                kvk_number: None,
                organisation_name_public: false,
                phone_number_public: false,
                kvk_number_public: false,
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

    #[test]
    fn test_sha256_hex_matches_business_portal_format() {
        // Matches `createHash('sha256').update(raw).digest('hex')` used by
        // postguard-business/src/lib/server/services/api-keys.ts. Pinning this
        // value guarantees both sides agree on the hash encoding.
        assert_eq!(
            sha256_hex("PG-test-key"),
            "85e74a724a8252e6b9feeb05c47e452de5a9ab9eda70ebfa7cdee7dc78b369dd"
        );
    }

    /// Regression test for the startup fragility where the PKG exited when the
    /// IRMA server was unreachable while the Jwt auth middleware initialized:
    /// startup must succeed, and JWT requests must degrade to a clean error
    /// (503 upstream) instead of the worker never coming up.
    #[actix_web::test]
    async fn test_jwt_auth_starts_when_irma_unreachable() {
        use actix_web::{test, web, App, HttpResponse};

        // Port 1 on localhost: nothing listens there, connections fail fast.
        let unreachable = "http://127.0.0.1:1".to_string();

        // Previously `new_transform` fetched the key here and failed, so
        // `init_service` itself would panic ("can not start server service").
        let app = test::init_service(
            App::new().service(
                web::resource("/probe")
                    .wrap(Auth::new(unreachable, AuthType::Jwt))
                    .route(web::get().to(|| async { HttpResponse::Ok().finish() })),
            ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/probe")
            .insert_header(("Authorization", "Bearer not.a.jwt"))
            .to_request();
        let err = test::try_call_service(&app, req)
            .await
            .expect_err("request must fail cleanly while the IRMA server is unreachable");
        assert_eq!(
            err.as_response_error().status_code(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
