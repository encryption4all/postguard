mod config;
mod email;
mod error;
mod metrics;
mod store;

use std::sync::Arc;
use std::time::Duration;

use crate::config::CryptifyConfig;
use crate::email::{render_confirmation_email, render_recipient_email, send_email, RenderedEmail};
use crate::error::{Error, PayloadTooLargeBody};
use crate::metrics::{
    detect_channel, parse_client_version, storage_sampler, Metrics, CHANNEL_UNKNOWN,
    CLIENT_VERSION_HEADER,
};

use std::path::Path;
use std::str::FromStr;

use pg_core::api::Parameters;
use pg_core::artifacts::VerifyingKey;
use pg_core::client::rust::stream::UnsealerStreamConfig;
use pg_core::client::Unsealer;
use pg_core::identity::Policy;

use tokio_util::compat::TokioAsyncReadCompatExt;

use sha2::Digest;
use std::fmt::Write;

use rocket::tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use rocket::{
    data::ToByteUnit, fairing::AdHoc, figment::Figment, get, http::Header, launch, post, put,
    request::FromRequest, response::Responder, routes, serde::json::Json, Build, Data, Rocket,
    State,
};

use rocket::http::Method;
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};

use serde::{Deserialize, Serialize};
use store::{FileState, LastChunkRecord, SenderClaim, Store};

#[derive(Serialize, Deserialize)]
struct InitBody {
    recipient: String,
    #[serde(rename = "mailContent")]
    mail_content: String,
    #[serde(rename = "mailLang")]
    mail_lang: email::Language,
    confirm: bool,
    /// Whether to email each recipient with a download link. Optional;
    /// defaults to `true` to preserve existing client behaviour. Set to
    /// `false` when the encrypted payload reaches the recipients through
    /// another channel (e.g. an email add-in delivering the message from
    /// the user's own mailbox) and a Cryptify-sent notification would be
    /// a duplicate. The recipient list itself is still validated and
    /// stored — only the SMTP delivery is skipped.
    #[serde(rename = "notifyRecipients", default = "default_true")]
    notify_recipients: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct InitResponse {
    uuid: String,
    /// Bearer credential for the cross-refresh-resume status endpoint
    /// (`GET /fileupload/{uuid}/status`). The client stores this alongside
    /// the UUID — typically in IndexedDB — and sends it back in an
    /// `X-Recovery-Token` header on resume. Hex-encoded 32-byte random.
    recovery_token: String,
    /// Ceiling on a single chunk PUT, in bytes: the server rejects any
    /// `PUT /fileupload/{uuid}` whose `Content-Range` spans more than this.
    /// A client may send smaller chunks. Always `config.chunk_size()`, the
    /// same accessor the enforcement path reads, so a client that sizes its
    /// chunks from this field cannot be out of step with the deployment.
    max_chunk_size_bytes: u64,
    /// This session's upload challenge, hex-encoded 32-byte random. The client
    /// signs the *decoded* bytes with its signing key, under the uuid as the
    /// context, and returns the signature base64-encoded in an
    /// `X-PostGuard-Proof` header on finalize — which is what proves the
    /// uploader holds the key for the identity their container claims.
    /// Answering is optional: an upload that does not answer finalizes as
    /// [`SenderClaim::Unproven`], and is not refused for it.
    challenge: String,
}

struct CryptifyToken(String);

impl From<CryptifyToken> for Header<'static> {
    fn from(token: CryptifyToken) -> Header<'static> {
        Header::new("cryptifytoken", token.0)
    }
}

#[derive(Responder)]
struct InitResponder {
    inner: Json<InitResponse>,
    cryptify_token: CryptifyToken,
}

/// Request guard that derives the traffic source channel from the request
/// headers for metrics labelling.
struct ClientHeaders {
    channel: String,
    /// Raw `X-POSTGUARD-CLIENT-VERSION` value (`host,host_version,app,app_version`),
    /// kept verbatim for logging so exact client versions are greppable.
    client_version: Option<String>,
    /// The `app` field of the client-version header, used as the
    /// `cryptify_uploads_by_app_total` metric label. `None` when the header
    /// is absent or malformed.
    client_app: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientHeaders {
    type Error = std::convert::Infallible;

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        let client_version = request
            .headers()
            .get_one(CLIENT_VERSION_HEADER)
            .map(str::to_string);
        let client_app = client_version
            .as_deref()
            .and_then(parse_client_version)
            .map(|cv| cv.app);
        rocket::request::Outcome::Success(ClientHeaders {
            channel: detect_channel(request.headers()),
            client_version,
            client_app,
        })
    }
}

#[get("/health")]
fn health() -> &'static str {
    "OK"
}

/// Request guard protecting `/metrics`. When `metrics_token` is configured,
/// the endpoint requires `Authorization: Bearer <token>` (constant-time
/// compared); otherwise it stays open (a startup warning is logged). This
/// auth lives in the app rather than the ingress so the protection travels
/// with cryptify to every deployment, including external hosts we can't
/// firewall.
struct MetricsAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MetricsAuth {
    type Error = ();
    async fn from_request(request: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self, ()> {
        let expected = request
            .rocket()
            .state::<CryptifyConfig>()
            .and_then(CryptifyConfig::metrics_token);

        // No token configured → metrics is open (warned about at startup).
        let Some(expected) = expected else {
            return rocket::request::Outcome::Success(MetricsAuth);
        };

        let presented = request
            .headers()
            .get_one("Authorization")
            .and_then(|h| {
                h.strip_prefix("Bearer ")
                    .or_else(|| h.strip_prefix("bearer "))
            })
            .map(str::trim);

        match presented {
            Some(token) if constant_time_eq(token, expected) => {
                rocket::request::Outcome::Success(MetricsAuth)
            }
            _ => rocket::request::Outcome::Error((rocket::http::Status::Unauthorized, ())),
        }
    }
}

#[get("/metrics")]
fn metrics_endpoint(
    _auth: MetricsAuth,
    metrics: &State<Arc<Metrics>>,
) -> rocket::response::content::RawText<String> {
    rocket::response::content::RawText(metrics.render())
}

/// Extract a `PG-…` bearer token from an Authorization header value, or
/// `None` for any other shape (missing, wrong scheme, non-PG prefix). Kept
/// as a pure helper so the parsing rules are unit-testable without HTTP.
fn extract_pg_bearer(header: Option<&str>) -> Option<&str> {
    let token = header
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)?;
    if token.starts_with("PG-") {
        Some(token)
    } else {
        None
    }
}

/// HTTP client for talking to pg-pkg's `/v2/api-key/validate` endpoint.
/// Held as Rocket state so the per-request `ApiKey` guard can call it.
struct PkgClient {
    http: reqwest::Client,
    pkg_url: String,
}

/// Total wall-clock budget for retrying pg-pkg validation when the call
/// errors out (network errors, 5xx). Authoritative responses (2xx with
/// validated tenant, 401/403 unrecognised key) short-circuit immediately —
/// retrying them would not change the outcome.
const PKG_VALIDATE_RETRY_BUDGET: Duration = Duration::from_secs(30);
const PKG_VALIDATE_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const PKG_VALIDATE_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Total wall-clock budget for fetching the IBS verifying key from pg-pkg at
/// startup. Long enough to ride out a PKG that is still booting during a
/// rolling deploy; when the budget is exhausted the process still exits with
/// a clear error, so a misconfigured `pkg_url` does not fail silently.
const PKG_PARAMS_RETRY_BUDGET: Duration = Duration::from_secs(120);
const PKG_PARAMS_INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const PKG_PARAMS_MAX_BACKOFF: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
struct ValidateResponse {
    tenant_id: String,
    #[allow(dead_code)]
    #[serde(default)]
    organisation_name: Option<String>,
    /// Email template linked to this API key on pg-pkg (postguard#86).
    /// `None` when the tenant has no template configured. Surfaced by the
    /// `GET /email-template` endpoint so API-key callers can fetch the
    /// notification body associated with their key.
    #[serde(default)]
    email_template: Option<String>,
}

#[derive(Debug)]
enum ValidationOutcome {
    /// No `Authorization: Bearer PG-…` header — caller is default tier.
    NoCredentials,
    /// pg-pkg confirmed the key. Carries the tenant id (uuid) and the
    /// email template linked to the key, if any.
    Validated {
        tenant: String,
        email_template: Option<String>,
    },
    /// pg-pkg returned an authoritative rejection (401/403). Caller is
    /// degraded to default tier — their fake/expired key won't earn the
    /// higher tier, but they can still upload up to the default cap.
    Rejected,
    /// pg-pkg was unreachable for the full retry budget. Caller is treated
    /// as default tier *unless* they exceed the default cap, at which point
    /// the chunk/finalize handler returns 503.
    PkgUnreachable,
}

impl PkgClient {
    fn new(pkg_url: String) -> Self {
        let http = reqwest::Client::builder()
            // Per-request timeout — bounded by the retry budget regardless,
            // but a low ceiling per attempt keeps the loop responsive.
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client build");
        Self { http, pkg_url }
    }

    async fn validate(&self, header: Option<&str>) -> ValidationOutcome {
        let Some(token) = extract_pg_bearer(header).map(str::to_owned) else {
            return ValidationOutcome::NoCredentials;
        };

        let url = format!("{}/v2/api-key/validate", self.pkg_url.trim_end_matches('/'));

        let deadline = rocket::tokio::time::Instant::now() + PKG_VALIDATE_RETRY_BUDGET;
        let mut backoff = PKG_VALIDATE_INITIAL_BACKOFF;
        loop {
            match self.http.get(&url).bearer_auth(&token).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<ValidateResponse>().await {
                        Ok(body) => {
                            return ValidationOutcome::Validated {
                                tenant: body.tenant_id,
                                email_template: body.email_template,
                            }
                        }
                        Err(e) => {
                            log::error!("pg-pkg /api-key/validate parse failed: {}", e);
                            return ValidationOutcome::PkgUnreachable;
                        }
                    }
                }
                Ok(resp) if matches!(resp.status().as_u16(), 401 | 403) => {
                    return ValidationOutcome::Rejected;
                }
                Ok(resp) => {
                    log::warn!(
                        "pg-pkg /api-key/validate returned status {} — will retry",
                        resp.status()
                    );
                }
                Err(e) => {
                    log::warn!(
                        "pg-pkg /api-key/validate request failed: {} — will retry",
                        e
                    );
                }
            }

            let now = rocket::tokio::time::Instant::now();
            if now + backoff >= deadline {
                return ValidationOutcome::PkgUnreachable;
            }
            rocket::tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(PKG_VALIDATE_MAX_BACKOFF);
        }
    }
}

/// Result of validating an `Authorization: Bearer PG-…` header against
/// pg-pkg. `tenant` is `Some` only on success; `validation_failed` is true
/// only when a PG-prefixed bearer was supplied but pg-pkg was unreachable.
/// `email_template` carries the template pg-pkg linked to the key, when the
/// key validated and a template is configured.
struct ApiKey {
    tenant: Option<String>,
    validation_failed: bool,
    email_template: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey {
    type Error = ();
    async fn from_request(req: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self, ()> {
        let header = req.headers().get_one("Authorization");
        let Some(client) = req.rocket().state::<PkgClient>() else {
            log::error!("PkgClient missing from Rocket state — treating request as default tier");
            return rocket::request::Outcome::Success(ApiKey {
                tenant: None,
                validation_failed: false,
                email_template: None,
            });
        };
        let outcome = client.validate(header).await;
        let api_key = match outcome {
            ValidationOutcome::Validated {
                tenant,
                email_template,
            } => ApiKey {
                tenant: Some(tenant),
                validation_failed: false,
                email_template,
            },
            ValidationOutcome::NoCredentials | ValidationOutcome::Rejected => ApiKey {
                tenant: None,
                validation_failed: false,
                email_template: None,
            },
            ValidationOutcome::PkgUnreachable => {
                log::warn!(
                    "pg-pkg unreachable during API-key validation; degrading to default tier (over-default uploads will 503)"
                );
                ApiKey {
                    tenant: None,
                    validation_failed: true,
                    email_template: None,
                }
            }
        };
        rocket::request::Outcome::Success(api_key)
    }
}

/// Request guard for routes that require a *validated* pg-pkg API key.
///
/// Unlike [`ApiKey`], whose `FromRequest` always succeeds (degrading callers
/// without a valid key to the anonymous "default tier"), this guard **fails**
/// the request when no valid credentials are presented:
/// - `NoCredentials` / `Rejected` → `401 Unauthorized`
/// - `PkgUnreachable` → `503 Service Unavailable` (we cannot confirm the key)
///
/// A route carrying this guard is therefore authenticated by construction —
/// the "authenticated" intent is enforced by the type system rather than by a
/// guard that always succeeds and leaves the check to the handler.
struct ValidatedApiKey {
    tenant: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ValidatedApiKey {
    type Error = ();
    async fn from_request(req: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self, ()> {
        let header = req.headers().get_one("Authorization");
        let Some(client) = req.rocket().state::<PkgClient>() else {
            log::error!("PkgClient missing from Rocket state — rejecting authenticated request");
            return rocket::request::Outcome::Error((rocket::http::Status::ServiceUnavailable, ()));
        };
        match client.validate(header).await {
            ValidationOutcome::Validated { tenant, .. } => {
                rocket::request::Outcome::Success(ValidatedApiKey { tenant })
            }
            ValidationOutcome::NoCredentials | ValidationOutcome::Rejected => {
                rocket::request::Outcome::Error((rocket::http::Status::Unauthorized, ()))
            }
            ValidationOutcome::PkgUnreachable => {
                log::warn!(
                    "pg-pkg unreachable during API-key validation on an authenticated route; returning 503"
                );
                rocket::request::Outcome::Error((rocket::http::Status::ServiceUnavailable, ()))
            }
        }
    }
}

#[post("/fileupload/init", data = "<request>")]
async fn upload_init(
    config: &State<CryptifyConfig>,
    store: &State<Store>,
    api_key: ApiKey,
    request: Json<InitBody>,
    client_headers: ClientHeaders,
) -> Result<InitResponder, Error> {
    let current_time = chrono::offset::Utc::now().timestamp();

    let recipient: lettre::message::Mailboxes = request
        .recipient
        .parse()
        .map_err(|e| Error::BadRequest(Some(format!("Could not parse e-mail address: {}", e))))?;

    let uuid = uuid::Uuid::new_v4().hyphenated().to_string();

    if let Err(e) = File::create(Path::new(config.data_dir()).join(&uuid)).await {
        log::error!("{}", e);
        return Err(Error::InternalServerError(None));
    }

    let init_cryptify_token = bytes_to_hex(&rand::random::<[u8; 32]>());
    let recovery_token = bytes_to_hex(&rand::random::<[u8; 32]>());
    let challenge = bytes_to_hex(&rand::random::<[u8; 32]>());

    log::info!(
        "upload_init uuid={} channel={} client_version={:?}",
        uuid,
        client_headers.channel,
        client_headers.client_version
    );

    store.create(
        uuid.clone(),
        FileState {
            cryptify_token: init_cryptify_token.clone(),
            uploaded: 0,
            expires: current_time + 1_209_600,
            recipients: recipient,
            mail_content: request.mail_content.clone(),
            mail_lang: request.mail_lang.clone(),
            sender: None,
            sender_attributes: Vec::new(),
            confirm: request.confirm,
            source_channel: client_headers.channel,
            client_version: client_headers.client_version,
            client_app: client_headers.client_app,
            notify_recipients: request.notify_recipients,
            api_key_tenant: api_key.tenant,
            api_key_validation_failed: api_key.validation_failed,
            last_chunk: None,
            // Only the digest is kept: the plaintext below is the client's
            // copy, and `upload_status` re-hashes whatever it is presented.
            recovery_token_hash: store::hash_recovery_token(&recovery_token),
            challenge: Some(challenge.clone()),
            // Nothing has been proved yet, and nothing here may claim
            // otherwise: the only place a `SenderClaim` is written is the
            // verification at finalize.
            sender_claim: None,
        },
    );

    Ok(InitResponder {
        inner: Json(InitResponse {
            uuid,
            recovery_token,
            max_chunk_size_bytes: config.chunk_size(),
            challenge,
        }),
        cryptify_token: CryptifyToken(init_cryptify_token),
    })
}

struct ContentRange {
    size: Option<u64>,
    start: Option<u64>,
    end: Option<u64>,
}

impl FromStr for ContentRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let unit = parts.next().ok_or("Missing unit")?;
        let range = parts.next().ok_or("Missing range")?;
        if parts.next().is_some() {
            return Err("Excess data".into());
        }
        if unit != "bytes" {
            return Err(format!("Unknown unit {}", unit));
        }
        let mut rangeparts = range.split('/');
        let range = rangeparts
            .next()
            .ok_or("Missing lower-upper part of range")?;
        let size = rangeparts.next().ok_or("Missing size part of range")?;
        if rangeparts.next().is_some() {
            return Err("Excess data in range".into());
        }
        let size = if size != "*" {
            Some(size.parse::<u64>().map_err(|e| e.to_string())?)
        } else {
            None
        };
        if range != "*" {
            let mut rangeparts = range.split('-');
            let start = rangeparts
                .next()
                .ok_or("Missing start of range")?
                .parse::<u64>()
                .map_err(|e| e.to_string())?;
            let end = rangeparts
                .next()
                .ok_or("Missing end of range")?
                .parse::<u64>()
                .map_err(|e| e.to_string())?;
            Ok(ContentRange {
                size,
                start: Some(start),
                end: Some(end),
            })
        } else {
            Ok(ContentRange {
                size,
                start: None,
                end: None,
            })
        }
    }
}

struct UploadHeaders {
    cryptify_token: String,
    content_range: ContentRange,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UploadHeaders {
    type Error = String;

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        let cryptify_token = match request.headers().get_one("CryptifyToken") {
            Some(cryptify_token) => cryptify_token,
            None => {
                return rocket::request::Outcome::Error((
                    rocket::http::Status::BadRequest,
                    "Missing Cryptify Token header".into(),
                ))
            }
        }
        .to_string();
        let content_range = match request.headers().get_one("Content-Range") {
            Some(content_range) => content_range,
            None => {
                return rocket::request::Outcome::Error((
                    rocket::http::Status::BadRequest,
                    "Missing content range".into(),
                ))
            }
        }
        .parse::<ContentRange>();
        let content_range = match content_range {
            Ok(v) => v,
            Err(e) => {
                return rocket::request::Outcome::Error((rocket::http::Status::BadRequest, e))
            }
        };

        rocket::request::Outcome::Success(UploadHeaders {
            cryptify_token,
            content_range,
        })
    }
}

#[derive(Responder)]
struct UploadResponder {
    body: (),
    cryptify_token: CryptifyToken,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(s, "{:02x}", byte).unwrap();
    }
    s
}

/// The inverse of [`bytes_to_hex`]: `None` for an odd length or any byte that
/// is not a hex digit. Works on bytes rather than `char`s so a non-ASCII input
/// is rejected instead of being sliced through a character.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }

    bytes
        .chunks(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

fn compute_hash(cryptify_token: &[u8], data: &[u8]) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(cryptify_token);
    hash.update(data);
    bytes_to_hex(&hash.finalize())
}

/// Wire-level error message for a `CryptifyToken` mismatch. Reused by both
/// `check_cryptify_token` (the finalize path) and the chunk classifier so the
/// message can't drift silently between call sites.
const TOKEN_MISMATCH_MSG: &str = "Cryptify Token header does not match";

/// Caller-facing body for 5xx (`InternalServerError` / `ServiceUnavailable`)
/// responses. Detailed diagnostics are written server-side via `log::error!`
/// rather than returned to HTTP clients, so operators keep observability
/// without leaking internal implementation details to callers
/// (GHSA-r95f-qf3j-xccw).
const GENERIC_INTERNAL_ERROR_MSG: &str = "an internal error occurred";

/// Constant-time compare of a presented `CryptifyToken` against the expected
/// value. Both are hex-encoded SHA-256 strings; `subtle::ConstantTimeEq` keeps
/// the timing independent of where the bytes first differ, mirroring
/// `recovery_tokens_match`. A network timing oracle against these 256-bit
/// high-entropy tokens is impractical, but we compare them in constant time
/// for consistency with the recovery-token path.
fn cryptify_tokens_match(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    if presented.len() != expected.len() {
        return false;
    }
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn check_cryptify_token(header: &str, expected: &str) -> Result<(), Error> {
    if !cryptify_tokens_match(header, expected) {
        return Err(Error::BadRequest(Some(TOKEN_MISMATCH_MSG.to_owned())));
    }
    Ok(())
}

#[put("/fileupload/<uuid>", data = "<data>")]
async fn upload_chunk(
    config: &State<CryptifyConfig>,
    store: &State<Store>,
    uuid: &str,
    headers: UploadHeaders,
    data: Data<'_>,
) -> Result<UploadResponder, Error> {
    if uuid::Uuid::parse_str(uuid).is_err() {
        return Err(Error::upload_session_not_found(uuid, "invalid_uuid"));
    }

    let state = match store.get(uuid) {
        Some(v) => v,
        None => return Err(Error::upload_session_not_found(uuid, "expired_or_unknown")),
    };
    let mut state = state.lock().await;

    let start = headers
        .content_range
        .start
        .ok_or_else(|| Error::BadRequest(Some("Could not read Content-Range start".to_owned())))?;
    let end = headers
        .content_range
        .end
        .ok_or_else(|| Error::BadRequest(Some("Could not read Content-Range end".to_owned())))?;

    if start >= end {
        return Err(Error::BadRequest(Some(
            "Incorrect Content-Range header".to_owned(),
        )));
    }

    if end - start > config.chunk_size() {
        return Err(Error::BadRequest(Some(format!(
            "File chunk too large; the maximum is {} bytes",
            config.chunk_size()
        ))));
    }

    // Cheap pre-check before reading the body, so a leaked UUID can't be
    // used to force the server to buffer up to `chunk_size` bytes per
    // request just to be rejected. Mirrors the structural part of
    // `classify_chunk_request` — we only commit to reading the body when
    // the request looks like either a normal next chunk or a candidate
    // replay of the last committed chunk.
    let is_normal_next = state.uploaded == start
        && cryptify_tokens_match(&headers.cryptify_token, &state.cryptify_token);
    let is_replay_candidate = state.last_chunk.as_ref().is_some_and(|last| {
        last.prev_uploaded == start
            && cryptify_tokens_match(&headers.cryptify_token, &last.prev_token)
    });
    if !is_normal_next && !is_replay_candidate {
        if state.uploaded != start {
            return Err(Error::BadRequest(Some(
                "Incorrect Content-Range header".to_owned(),
            )));
        }
        return Err(Error::BadRequest(Some(TOKEN_MISMATCH_MSG.to_owned())));
    }

    let body = data
        .open((end - start).bytes())
        .into_bytes()
        .await
        .map_err(|_| Error::BadRequest(Some("Could not read data from request".to_owned())))?;
    if !body.is_complete() || body.len() as u64 != end - start {
        return Err(Error::BadRequest(Some("Data not complete".to_owned())));
    }
    let body = body.into_inner();

    // Three branches: normal next chunk, idempotent retry of the last
    // committed chunk, or rejection.
    match classify_chunk_request(&state, &headers.cryptify_token, start, &body) {
        ChunkClassification::NormalNext => {}
        ChunkClassification::ReplayLastChunk(token) => {
            drop(state);
            store.touch(uuid);
            return Ok(UploadResponder {
                body: (),
                cryptify_token: CryptifyToken(token),
            });
        }
        ChunkClassification::Reject(err) => return Err(err),
    }

    let per_upload_limit = if state.api_key_tenant.is_some() {
        config.api_key_per_upload_limit()
    } else {
        config.per_upload_limit()
    };
    if end > per_upload_limit {
        // If the caller presented an API key but pg-pkg was unreachable at
        // init time, we degraded them to the default tier. Below the default
        // cap that's silent; here, where we'd reject, surface 503 so the
        // client knows the higher tier *might* have applied if pg-pkg had
        // been reachable. Within-default uploads keep flowing as today.
        if state.api_key_validation_failed {
            log::error!(
                "pg-pkg was unreachable while validating the API key; cannot apply the higher upload tier"
            );
            return Err(Error::ServiceUnavailable(Some(
                GENERIC_INTERNAL_ERROR_MSG.to_owned(),
            )));
        }
        return Err(Error::PayloadTooLarge(PayloadTooLargeBody::per_upload(
            per_upload_limit,
            state.uploaded,
        )));
    }

    let mut file = match OpenOptions::new()
        .write(true)
        .open(Path::new(config.data_dir()).join(uuid))
        .await
    {
        Ok(v) => v,
        Err(_) => return Err(Error::upload_session_not_found(uuid, "file_missing")),
    };

    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(|e| {
            log::error!("could not seek in upload file: {}", e);
            Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
        })?;

    file.write_all(&body).await.map_err(|e| {
        log::error!("could not write chunk to upload file: {}", e);
        Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
    })?;

    let prev_token = headers.cryptify_token;
    let shasum = compute_hash(prev_token.as_bytes(), &body);
    state.cryptify_token = shasum.clone();
    state.uploaded += end - start;
    state.last_chunk = Some(LastChunkRecord {
        prev_token,
        prev_uploaded: start,
        response_token: shasum.clone(),
    });

    // Write the advanced chain through to SQLite before the response leaves:
    // the client treats the token it gets back as committed, so the durable
    // row must not lag behind it. A database failure is logged, not
    // propagated — the chunk is already on disk and in memory.
    store.persist_session(uuid, &state);

    drop(state);
    store.touch(uuid);

    Ok(UploadResponder {
        body: (),
        cryptify_token: CryptifyToken(shasum),
    })
}

/// Outcome of inspecting a chunk PUT against the current `FileState`.
enum ChunkClassification {
    /// The expected next chunk in the rolling-token chain — caller proceeds
    /// to the normal write path.
    NormalNext,
    /// The just-completed chunk being retried after a lost response. Caller
    /// returns this token to the client without re-writing or double-counting.
    ReplayLastChunk(String),
    /// Reject the request with this error — the standard 400 you'd get
    /// before idempotent-retry support, plus a stricter 400 when the
    /// request looks like a retry but the body bytes (or their length)
    /// diverge from the cached chunk. Never accept different bytes for
    /// the same offset.
    Reject(Error),
}

fn classify_chunk_request(
    state: &FileState,
    request_token: &str,
    start: u64,
    body: &[u8],
) -> ChunkClassification {
    if state.uploaded == start && cryptify_tokens_match(request_token, &state.cryptify_token) {
        return ChunkClassification::NormalNext;
    }

    if let Some(last) = state.last_chunk.as_ref() {
        if cryptify_tokens_match(request_token, &last.prev_token) && start == last.prev_uploaded {
            // Recompute the rolling hash over the incoming body. Identity
            // is implicit in the rolling-token construction itself: if the
            // hash matches `response_token`, the body is byte-identical to
            // the original chunk (modulo a SHA-256 collision, which would
            // also break the rolling chain). Length divergence surfaces
            // here too.
            if compute_hash(last.prev_token.as_bytes(), body) == last.response_token {
                return ChunkClassification::ReplayLastChunk(last.response_token.clone());
            }
            return ChunkClassification::Reject(Error::BadRequest(Some(
                "Idempotent retry: body differs from the original chunk".to_owned(),
            )));
        }
    }

    if state.uploaded != start {
        return ChunkClassification::Reject(Error::BadRequest(Some(
            "Incorrect Content-Range header".to_owned(),
        )));
    }

    ChunkClassification::Reject(Error::BadRequest(Some(TOKEN_MISMATCH_MSG.to_owned())))
}

/// Header the uploader answers the init challenge in. Its value is the
/// signature `pg-wasm`'s `signChallenge` returns, base64-encoded.
const PROOF_HEADER: &str = "X-PostGuard-Proof";

struct FinalizeHeaders {
    cryptify_token: String,
    content_range: ContentRange,
    /// The [`PROOF_HEADER`] value, when the client sent one. Absent for every
    /// client that has not shipped the header yet, which is not an error: it
    /// finalizes as [`SenderClaim::Unproven`].
    proof: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for FinalizeHeaders {
    type Error = String;

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        let cryptify_token = match request.headers().get_one("CryptifyToken") {
            Some(cryptify_token) => cryptify_token,
            None => {
                return rocket::request::Outcome::Error((
                    rocket::http::Status::BadRequest,
                    "Missing Cryptify Token header".into(),
                ))
            }
        }
        .to_string();

        let content_range = match request.headers().get_one("Content-Range") {
            Some(content_range) => content_range,
            None => {
                return rocket::request::Outcome::Error((
                    rocket::http::Status::BadRequest,
                    "Missing content range".into(),
                ))
            }
        };

        let content_range = match content_range.parse::<ContentRange>() {
            Ok(v) => v,
            Err(e) => {
                return rocket::request::Outcome::Error((rocket::http::Status::BadRequest, e))
            }
        };
        rocket::request::Outcome::Success(FinalizeHeaders {
            cryptify_token,
            content_range,
            proof: request.headers().get_one(PROOF_HEADER).map(str::to_owned),
        })
    }
}

/// The key the rolling limit accounts against.
///
/// A validated API key accounts per tenant. `api-key:<tenant>` is not an
/// identity attribute, carries no canonicalization rule, and is used exactly
/// as the key named it; it also wins over the sender, so one tenant cannot
/// evade quota by varying sender attributes.
///
/// Everything else accounts per sender email, and that value is read verbatim
/// out of the uploaded container's public signing policy, so it is
/// caller-chosen even when the sender is entirely genuine. `Policy::derive`
/// canonicalizes before it derives the signer's identity (postguard#250), so
/// one signing key for `bob@example.com` also verifies a container storing
/// `Bob@Example.COM`, and the raw spelling is what reaches us as `pub_id`.
/// Canonicalizing here is what keeps those spellings in one bucket instead of
/// minting a fresh 14-day quota per capitalization.
fn accounting_key(
    api_key_tenant: Option<&str>,
    email_attribute: &str,
    sender: Option<&str>,
) -> Option<String> {
    match api_key_tenant {
        Some(tenant) => Some(format!("api-key:{}", tenant)),
        None => sender.map(|s| pg_core::identity::canonicalize(email_attribute, s)),
    }
}

/// Decode a [`PROOF_HEADER`] value into an IBS signature.
///
/// The encoding is the one the client is handed: `pg-wasm`'s `signChallenge`
/// returns `bincode_compat::serialize` of the signature, and the client
/// base64s exactly those bytes. That serialization is a fixed `SIG_BYTES`
/// long, and extra bytes must not be able to ride along on an otherwise valid
/// proof. Two layers stop them and neither truncates: the buffer is exactly
/// `SIG_BYTES`, so `Base64::decode` refuses anything longer outright, and
/// `deserialize` needs all of them, so anything shorter is not a signature.
/// The length check below is that invariant written where a reader looks for
/// it, not a third layer.
///
/// `None` for anything that is not such a value; a malformed proof is a failed
/// proof, never an error.
fn decode_proof(header: &str) -> Option<pg_core::ibs::gg::Signature> {
    use base64ct::{Base64, Encoding};

    let mut buf = [0u8; pg_core::ibs::gg::SIG_BYTES];
    let bytes = Base64::decode(header, &mut buf).ok()?;
    if bytes.len() != pg_core::ibs::gg::SIG_BYTES {
        return None;
    }

    pg_core::bincode_compat::deserialize(bytes).ok()
}

/// Reduce the uploader's answer to this session's challenge to a
/// [`SenderClaim`]. The only place a `SenderClaim` is produced.
///
/// The signature is verified against the identity derived from the
/// container's *own* signing policy, so there is no claimed-identity field to
/// compare and no spelling to match: either the uploader holds the key for the
/// identity that policy derives to, or they do not.
/// [`pg_core::challenge::verify_challenge`] answers exactly that and reports
/// every way a proof can fail — including a policy no identity derives from —
/// as `false`, so there is no error branch here and each failure lands in the
/// same arm as a missing header.
///
/// A proof that is absent, malformed or simply wrong is `Unproven` all the
/// same, and none of them refuses the upload: what a deployment does about an
/// unproven sender is decided elsewhere, and rejecting here would break every
/// client that has not shipped the header.
fn sender_claim(
    vk: &VerifyingKey,
    pub_id: &Policy,
    uuid: &str,
    challenge: Option<&str>,
    proof: Option<&str>,
    email_attribute: &str,
) -> SenderClaim {
    let Some(proof) = proof else {
        return SenderClaim::Unproven;
    };

    let Some(challenge) = challenge else {
        // A session restored from a row written before challenges existed was
        // never given anything to answer.
        log::info!("finalize of {uuid} presented a proof for a session that has no challenge");
        return SenderClaim::Unproven;
    };

    let Some(challenge) = hex_to_bytes(challenge) else {
        log::error!("upload session {uuid} carries a challenge that is not hex");
        return SenderClaim::Unproven;
    };

    let Some(sig) = decode_proof(proof) else {
        log::info!("finalize of {uuid} presented a malformed {PROOF_HEADER}");
        return SenderClaim::Unproven;
    };

    if !pg_core::challenge::verify_challenge(vk, pub_id, uuid, &challenge, &sig) {
        log::info!(
            "finalize of {uuid} presented a proof that does not verify under the sender identity \
             its container claims"
        );
        return SenderClaim::Unproven;
    }

    // Read the claim off the canonical policy rather than the spellings the
    // container carries: canonicalizing is what `derive_ibs` did before the
    // signature was checked, so this is the identity the proof pinned. See
    // `SenderClaim`.
    let proven = pub_id.canonical();
    let Some(email) = proven
        .con
        .iter()
        .find(|attribute| attribute.atype == email_attribute)
        .and_then(|attribute| attribute.value.clone())
    else {
        // The proof holds, but the attribute carries no value, so there is no
        // address to attribute it to and nothing to claim. Unreachable for a
        // container a `Sealer` wrote — the public signing policy carries its
        // values — and `state.sender` is `None` here for the same reason.
        log::error!("finalize of {uuid} proved an identity with no {email_attribute} value");
        return SenderClaim::Unproven;
    };

    SenderClaim::Proven {
        email,
        attrs: proven
            .con
            .iter()
            .filter(|attribute| attribute.atype != email_attribute)
            .filter_map(|attribute| {
                attribute
                    .value
                    .clone()
                    .map(|value| (attribute.atype.clone(), value))
            })
            .collect(),
    }
}

#[post("/fileupload/finalize/<uuid>")]
async fn upload_finalize(
    config: &State<CryptifyConfig>,
    store: &State<Store>,
    vk: &State<Parameters<VerifyingKey>>,
    metrics: &State<Arc<Metrics>>,
    headers: FinalizeHeaders,
    uuid: &str,
) -> Result<(), Error> {
    let state = match store.get(uuid) {
        Some(v) => v,
        None => return Err(Error::upload_session_not_found(uuid, "expired_or_unknown")),
    };
    let mut state = state.lock().await;

    check_cryptify_token(&headers.cryptify_token, &state.cryptify_token)?;

    if headers.content_range.size != Some(state.uploaded) {
        return Err(Error::UnprocessableEntity(None));
    }

    let mut file = File::open(Path::new(config.data_dir()).join(uuid))
        .await
        .map_err(|e| {
            log::error!("could not open upload file for finalize: {}", e);
            Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
        })?
        .compat();

    // The whole signing policy, not just its attributes: it is also what the
    // uploader's proof is verified against.
    let pub_id = Unsealer::<_, UnsealerStreamConfig>::new(&mut file, &vk.public_key)
        .await
        .map_err(|e| {
            log::error!("could not read postguard file during finalize: {}", e);
            Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
        })?
        .pub_id;

    // The attribute type carrying the sender's email is configurable
    // (postguard#236): test environments use a test-scheme type since pbdf
    // credentials cannot be issued outside production.
    let email_attribute = config.email_attribute();
    let sender = pub_id
        .con
        .iter()
        .find(|x| x.atype == email_attribute)
        .ok_or_else(|| {
            log::error!(
                "finalized upload has no email attribute ({email_attribute}) in postguard metadata"
            );
            Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
        })?
        .value
        .clone();

    let sender_attributes: Vec<(String, String)> = pub_id
        .con
        .iter()
        .filter(|x| x.atype != email_attribute)
        .filter_map(|x| x.value.clone().map(|v| (x.atype.clone(), v)))
        .collect();

    let rolling_limit = if state.api_key_tenant.is_some() {
        config.api_key_rolling_limit()
    } else {
        config.rolling_limit()
    };
    let now_secs = chrono::offset::Utc::now().timestamp();
    let accounting_key = accounting_key(
        state.api_key_tenant.as_deref(),
        email_attribute,
        sender.as_deref(),
    );
    if let Some(key) = accounting_key.as_deref() {
        let usage = store.get_usage(key, now_secs);
        log::info!(
            "Rolling limit check for {} (api_key_tenant={:?}): used={} + current={} vs limit={}",
            key,
            state.api_key_tenant,
            usage.used_bytes,
            state.uploaded,
            rolling_limit
        );
        if usage.used_bytes.saturating_add(state.uploaded) > rolling_limit {
            let uploaded = state.uploaded;
            drop(state);
            store.remove(uuid);
            let _ = rocket::tokio::fs::remove_file(Path::new(config.data_dir()).join(uuid)).await;
            return Err(Error::PayloadTooLarge(PayloadTooLargeBody::rolling_window(
                format!(
                    "Sender has exceeded the {}-day rolling limit of {} bytes",
                    config.rolling_window_days(),
                    rolling_limit
                ),
                rolling_limit,
                uploaded,
            )));
        }
    }

    let claim = sender_claim(
        &vk.public_key,
        &pub_id,
        uuid,
        state.challenge.as_deref(),
        headers.proof.as_deref(),
        email_attribute,
    );

    state.sender = sender.clone();
    state.sender_attributes = sender_attributes;
    // A proof already established must survive a retried finalize: the client
    // may repeat the request without the header, and that must not erase what
    // was proved. Only the verification above produces a `Proven`, so this
    // keeps the claim written once in the direction that matters.
    if !matches!(state.sender_claim, Some(SenderClaim::Proven { .. })) {
        state.sender_claim = Some(claim);
    }

    // Persist the finalize transition (the sender is only known now) before
    // the notification email goes out, so the durable row is never behind the
    // side effects the client's request produced.
    store.persist_session(uuid, &state);

    send_email(config, &state, uuid).await.map_err(|e| {
        log::error!("could not send notification email: {}", e);
        Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
    })?;

    metrics.record_upload(&state.source_channel, state.uploaded);
    metrics.record_upload_app(state.client_app.as_deref().unwrap_or(CHANNEL_UNKNOWN));

    log::info!(
        "upload_finalize uuid={} channel={} client_version={:?} app={:?} bytes={} sender_proven={}",
        uuid,
        state.source_channel,
        state.client_version,
        state.client_app,
        state.uploaded,
        matches!(state.sender_claim, Some(SenderClaim::Proven { .. }))
    );

    if let Some(key) = accounting_key {
        store.record_upload(key, state.uploaded, now_secs);
    }

    Ok(())
}

/// Snapshot of an in-flight upload's rolling-token state, returned by
/// `GET /fileupload/{uuid}/status`. The client uses this to rehydrate a
/// session it lost track of (page refresh, tab crash) and feed the next
/// chunk PUT through the idempotent-retry path from #145. `prev_token`
/// and `prev_offset` are `None` until at least one chunk has been
/// committed — in that case the client just resumes from offset 0 with
/// `cryptify_token`.
#[derive(Serialize)]
struct UploadStatusResponse {
    uploaded: u64,
    cryptify_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_offset: Option<u64>,
}

/// Constant-time string equality. `subtle::ConstantTimeEq` makes the timing
/// independent of where the bytes start to differ — defeats timing oracles
/// on secret comparisons. Used for the recovery token and the `/metrics`
/// bearer token. A length difference returns early (lengths aren't secret).
fn constant_time_eq(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    if presented.len() != expected.len() {
        return false;
    }
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[get("/fileupload/<uuid>/status")]
async fn upload_status(
    store: &State<Store>,
    uuid: &str,
    recovery_token: RecoveryTokenHeader,
) -> Result<Json<UploadStatusResponse>, Error> {
    // Two-step auth-versus-existence ordering: present a 401 for missing /
    // malformed credentials regardless of UUID; once the credential is
    // structurally present, an unknown UUID *or* a value mismatch both
    // surface as 404 with `upload_session_not_found`. That collapsing is
    // deliberate — otherwise an attacker with a guessable UUID could send
    // any value and read 401 vs 404 to confirm which UUIDs have live
    // sessions.
    let state = store
        .get(uuid)
        .ok_or_else(|| Error::upload_session_not_found(uuid, "expired_or_unknown"))?;
    let state = state.lock().await;

    // Hash-versus-hash, never plaintext-versus-plaintext: the server does not
    // keep the token it issued, only `sha256` of it, which is the same thing a
    // session restored from SQLite after a restart holds. Both comparands are
    // fixed-length hex digests, so the constant-time compare has no length to
    // leak either.
    if !constant_time_eq(
        &store::hash_recovery_token(&recovery_token.0),
        &state.recovery_token_hash,
    ) {
        // Same body shape as evicted/unknown so the response doesn't leak
        // session existence to a token-guessing attacker.
        return Err(Error::upload_session_not_found(uuid, "expired_or_unknown"));
    }

    let (prev_token, prev_offset) = match state.last_chunk.as_ref() {
        Some(last) => (Some(last.prev_token.clone()), Some(last.prev_uploaded)),
        None => (None, None),
    };
    let response = UploadStatusResponse {
        uploaded: state.uploaded,
        cryptify_token: state.cryptify_token.clone(),
        prev_token,
        prev_offset,
    };

    drop(state);
    // The whole point of cross-refresh resume is to hand control back to
    // the client mid-upload — push the eviction deadline so the very next
    // chunk PUT doesn't 404 because the rehydrate window aged out.
    store.touch(uuid);
    Ok(Json(response))
}

/// Extractor for the `X-Recovery-Token` header. Missing or malformed
/// header → 401 from the route handler. Deliberately not reusing the
/// `Authorization: Bearer …` scheme: that channel already carries
/// `PG-…` API-key credentials for the upload-tier flow, and crossing
/// the two would invite middleware misrouting.
struct RecoveryTokenHeader(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RecoveryTokenHeader {
    type Error = ();
    async fn from_request(request: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self, ()> {
        let token = request.headers().get_one("X-Recovery-Token").and_then(|t| {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });
        match token {
            Some(t) => rocket::request::Outcome::Success(RecoveryTokenHeader(t)),
            None => rocket::request::Outcome::Error((rocket::http::Status::Unauthorized, ())),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct UsageResponse {
    email: String,
    used_bytes: u64,
    limit_bytes: u64,
    window_days: u64,
    per_upload_limit_bytes: u64,
    resets_at: Option<String>,
}

#[get("/usage?<email>")]
fn usage(
    config: &State<CryptifyConfig>,
    store: &State<Store>,
    api_key: ValidatedApiKey,
    email: Option<String>,
) -> Json<UsageResponse> {
    let now = chrono::offset::Utc::now().timestamp();
    // Usage is accounted per validated tenant, keyed by the tenant proven via
    // the `Authorization` header — never by a caller-supplied email. The
    // `ValidatedApiKey` guard has already rejected any unauthenticated caller
    // with 401, so there is no way to query usage for an arbitrary address and
    // hence no user-enumeration / activity-monitoring oracle. The `email`
    // query parameter is retained only so the response can echo it back for
    // frontends; it does not influence the lookup.
    let lookup_key = format!("api-key:{}", api_key.tenant);
    let usage = store.get_usage(&lookup_key, now);
    let resets_at = usage
        .oldest_expires_at
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    Json(UsageResponse {
        email: email.unwrap_or_default(),
        used_bytes: usage.used_bytes,
        limit_bytes: config.api_key_rolling_limit(),
        window_days: config.rolling_window_days(),
        per_upload_limit_bytes: config.api_key_per_upload_limit(),
        resets_at,
    })
}

/// Body of `GET /limits`: the default tier's upload limits.
///
/// `per_upload_limit_bytes` and `window_days` are spelled as
/// [`UsageResponse`] spells them. `rolling_limit_bytes` deliberately is not
/// `/usage`'s `limit_bytes`: the two responses report different tiers, and one
/// name for two tiers' numbers is how a client ends up displaying the wrong
/// one.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct LimitsResponse {
    per_upload_limit_bytes: u64,
    rolling_limit_bytes: u64,
    window_days: u64,
}

/// The default tier's upload limits, served to every caller alike.
///
/// Unauthenticated on purpose: both 413 bodies already state these numbers to
/// a caller holding no credentials, and a client needs them before it starts
/// an upload rather than after it has been rejected.
///
/// The response takes no credential guard and carries nothing per-tenant — no
/// `used_bytes`, no `resets_at`, no email — so it cannot vary by
/// `Authorization`. An endpoint whose contents depend on auth is how
/// GHSA-5rhx-xgvv-h78h happened; usage stays behind `/usage`'s guard.
#[get("/limits")]
fn limits(config: &State<CryptifyConfig>) -> Json<LimitsResponse> {
    Json(LimitsResponse {
        per_upload_limit_bytes: config.per_upload_limit(),
        rolling_limit_bytes: config.rolling_limit(),
        window_days: config.rolling_window_days(),
    })
}

/// Body returned by `GET /email-template` for a validated API key that has
/// a template configured on pg-pkg.
#[derive(Serialize)]
struct EmailTemplateResponse {
    /// Tenant the API key resolved to on pg-pkg.
    tenant_id: String,
    /// The email template linked to the key.
    email_template: String,
}

/// Map a validated (or rejected) [`ApiKey`] to the `GET /email-template`
/// outcome. Kept as a pure function so every branch — authorized, no
/// template, rejected key, pg-pkg unreachable — is unit-testable without
/// standing up the HTTP stack or a live pg-pkg.
fn resolve_email_template(api_key: ApiKey) -> Result<EmailTemplateResponse, Error> {
    match api_key.tenant {
        Some(tenant_id) => match api_key.email_template {
            Some(email_template) => Ok(EmailTemplateResponse {
                tenant_id,
                email_template,
            }),
            // The key is valid but no template is linked to it on pg-pkg.
            None => Err(Error::NotFound(Some(
                "No email template is configured for this API key".to_owned(),
            ))),
        },
        // No tenant: either no/invalid key (validation_failed == false) or
        // pg-pkg was unreachable while validating (validation_failed == true).
        None if api_key.validation_failed => {
            // Keep the pg-pkg dependency detail server-side rather than
            // leaking it in the response body (GHSA-r95f-qf3j-xccw); mirrors
            // the upload-tier 503 in `upload_chunk`.
            log::error!(
                "pg-pkg was unreachable while validating the API key for GET /email-template"
            );
            Err(Error::ServiceUnavailable(Some(
                GENERIC_INTERNAL_ERROR_MSG.to_owned(),
            )))
        }
        None => Err(Error::Unauthorized(Some(
            "A valid `Authorization: Bearer PG-…` API key is required".to_owned(),
        ))),
    }
}

/// Return the email template linked to the caller's API key on pg-pkg. The
/// key is validated through the same `ApiKey` request guard the upload
/// endpoints use. Returns 401 when no valid key is presented, 404 when the
/// key is valid but has no template configured, and 503 when pg-pkg could
/// not be reached to validate the key.
#[get("/email-template")]
fn email_template(api_key: ApiKey) -> Result<Json<EmailTemplateResponse>, Error> {
    resolve_email_template(api_key).map(Json)
}

/// Staging-only endpoint that returns the rendered notification email(s)
/// cryptify *would* deliver for an upload, so developers on the staging
/// website can preview the message without an SMTP transport. Gated on
/// `staging_mode = true`; returns `404 Not Found` everywhere else so
/// production reveals no surface.
#[derive(serde::Serialize)]
struct StagingPreviewResponse {
    recipients: Vec<RenderedEmail>,
    confirmation: Option<RenderedEmail>,
}

#[get("/staging/preview/<uuid>")]
async fn staging_preview(
    config: &State<CryptifyConfig>,
    store: &State<Store>,
    uuid: &str,
) -> Result<Json<StagingPreviewResponse>, rocket::http::Status> {
    if !config.staging_mode() {
        return Err(rocket::http::Status::NotFound);
    }
    let state_arc = store.get(uuid).ok_or(rocket::http::Status::NotFound)?;
    let state = state_arc.lock().await;

    let mut recipients = Vec::with_capacity(state.recipients.iter().count());
    for mailbox in state.recipients.iter() {
        let email = mailbox.email.to_string();
        match render_recipient_email(&state, config, &email, uuid) {
            Ok(r) => recipients.push(r),
            Err(e) => log::warn!(
                "staging_preview: failed to render recipient {} for {}: {}",
                email,
                uuid,
                e
            ),
        }
    }

    let confirmation = if state.confirm {
        match render_confirmation_email(&state, config, uuid) {
            Ok(opt) => opt,
            Err(e) => {
                log::warn!(
                    "staging_preview: failed to render confirmation for {}: {}",
                    uuid,
                    e
                );
                None
            }
        }
    } else {
        None
    };

    Ok(Json(StagingPreviewResponse {
        recipients,
        confirmation,
    }))
}

/// Parsed byte range derived from an HTTP `Range` header and the resource's
/// total size. Both endpoints are inclusive, per RFC 7233 §2.1.
#[derive(Debug, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end_inclusive: u64,
}

impl ByteRange {
    fn len(&self) -> u64 {
        self.end_inclusive - self.start + 1
    }
}

/// Parse a single-range `Range` header against a resource of `total_size`
/// bytes. Returns `None` for malformed, multi-range, or unsatisfiable
/// requests — the caller turns that into a 416. Supports `bytes=N-M`,
/// `bytes=N-`, and the suffix form `bytes=-N`. Multi-range is rejected
/// deliberately; resume only needs one range and the multipart/byteranges
/// response is not worth the complexity.
fn parse_range_header(header: &str, total_size: u64) -> Option<ByteRange> {
    let rest = header.strip_prefix("bytes=")?.trim();
    if rest.contains(',') {
        return None;
    }
    let (s, e) = rest.split_once('-')?;
    let s = s.trim();
    let e = e.trim();
    if s.is_empty() {
        let n: u64 = e.parse().ok()?;
        if n == 0 || total_size == 0 {
            return None;
        }
        let n = n.min(total_size);
        return Some(ByteRange {
            start: total_size - n,
            end_inclusive: total_size - 1,
        });
    }
    let start: u64 = s.parse().ok()?;
    if start >= total_size {
        return None;
    }
    let end_inclusive = if e.is_empty() {
        total_size - 1
    } else {
        let v: u64 = e.parse().ok()?;
        v.min(total_size - 1)
    };
    if end_inclusive < start {
        return None;
    }
    Some(ByteRange {
        start,
        end_inclusive,
    })
}

/// Cryptify stores upload payloads as flat UUID-named files under
/// `data_dir`. Reject anything that could escape that or address an
/// unintended path before touching the filesystem.
fn is_safe_download_segment(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && name != ".."
        && name != "."
}

/// Captures the inbound `Range` header (if any) without failing the request
/// when it's absent.
struct RangeHeader(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RangeHeader {
    type Error = std::convert::Infallible;
    async fn from_request(
        req: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        rocket::request::Outcome::Success(RangeHeader(
            req.headers().get_one("Range").map(|s| s.to_owned()),
        ))
    }
}

/// Wraps a pre-built `rocket::Response` so the route handler below can
/// return it as a `Responder`.
struct RawResponse(rocket::Response<'static>);

impl<'r> Responder<'r, 'static> for RawResponse {
    fn respond_to(self, _req: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        Ok(self.0)
    }
}

#[get("/filedownload/<filename>")]
async fn download(
    filename: &str,
    range: RangeHeader,
    config: &State<CryptifyConfig>,
) -> Result<RawResponse, rocket::http::Status> {
    use rocket::http::Status;
    use std::io::SeekFrom;

    if !is_safe_download_segment(filename) {
        return Err(Status::NotFound);
    }
    let path = Path::new(config.data_dir()).join(filename);
    let mut file = File::open(&path).await.map_err(|_| Status::NotFound)?;
    let total_size = file.metadata().await.map_err(|_| Status::NotFound)?.len();

    let mut builder = rocket::Response::build();
    builder.raw_header("Accept-Ranges", "bytes");

    match range.0 {
        Some(header) => match parse_range_header(&header, total_size) {
            Some(br) => {
                file.seek(SeekFrom::Start(br.start))
                    .await
                    .map_err(|_| Status::InternalServerError)?;
                let len = br.len();
                builder
                    .status(Status::PartialContent)
                    .raw_header(
                        "Content-Range",
                        format!("bytes {}-{}/{}", br.start, br.end_inclusive, total_size),
                    )
                    .raw_header("Content-Length", len.to_string())
                    .streamed_body(file.take(len));
            }
            None => {
                builder
                    .status(Status::RangeNotSatisfiable)
                    .raw_header("Content-Range", format!("bytes */{}", total_size));
            }
        },
        None => {
            builder
                .status(Status::Ok)
                .raw_header("Content-Length", total_size.to_string())
                .streamed_body(file);
        }
    }
    Ok(RawResponse(builder.finalize()))
}

/// Base Rocket figment shared by the production launch path and the integration
/// test harness. Body-size limits are applied later in [`build_rocket`] once
/// the merged config has been extracted (chunk_size is now configurable via
/// TOML, so it isn't known at this point in the test path).
pub fn default_figment() -> Figment {
    rocket::Config::figment()
}

/// Build the CORS fairing. Shared by the production launch path and the
/// preflight smoke tests so the header allow-list under test is the one
/// actually deployed (a test-local copy is how `X-Cryptify-Source` regressed
/// unnoticed when the website started sending it).
fn build_cors(allowed_origins: AllowedOrigins) -> rocket_cors::Cors {
    CorsOptions::default()
        .allowed_origins(allowed_origins)
        .allowed_methods(
            vec![Method::Get, Method::Post, Method::Put, Method::Delete]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        // Browser preflight needs to allow our custom request headers.
        // `Authorization` is here for the Bearer-API-key tier flow;
        // `cryptifytoken`, `content-range`, and `content-type` ride on
        // chunk PUTs; `x-recovery-token` authenticates GET /…/status;
        // `x-cryptify-source` tags requests for per-channel metrics;
        // `x-postguard-proof` carries the challenge signature on finalize,
        // where a missing entry breaks the upload rather than leaving it
        // `Unproven`.
        .allowed_headers(AllowedHeaders::some(&[
            "Authorization",
            "Content-Type",
            "Content-Range",
            "CryptifyToken",
            "Range",
            "X-Cryptify-Source",
            "X-PostGuard-Proof",
            "X-Recovery-Token",
            // Browser clients (pg-js) send this on every request; without it
            // in the preflight allowlist the browser blocks cross-origin
            // uploads. Captured for the per-app upload metric + logs.
            "X-POSTGUARD-CLIENT-VERSION",
        ]))
        .expose_headers(["cryptifytoken"].iter().map(ToString::to_string).collect())
        .max_age(Some(86400))
        .to_cors()
        .expect("unable to configure CORS")
}

/// Every route the service mounts. Single source of truth so the
/// `api-description.yaml` drift test can compare the spec against the routes
/// production actually serves instead of a hand-copied list.
fn api_routes() -> Vec<rocket::Route> {
    routes![
        health,
        metrics_endpoint,
        upload_init,
        upload_chunk,
        upload_finalize,
        upload_status,
        usage,
        limits,
        email_template,
        download,
        staging_preview
    ]
}

/// Build a Rocket instance from a pre-loaded config figment and verifying key.
///
/// Extracted so integration tests can inject their own figment (temp data_dir,
/// stubbed email sending) and their own `VerifyingKey` (from
/// `pg_core::test::TestSetup`) without needing a live PKG at startup.
pub fn build_rocket(figment: Figment, vk: Parameters<VerifyingKey>) -> Rocket<Build> {
    let config = figment
        .extract::<CryptifyConfig>()
        .expect("Missing configuration");

    // Raise Rocket's default body-size limits so chunked uploads up to
    // chunk_size do not trip "Data limit reached while reading the request
    // body". `data.open((end - start).bytes())` already caps the per-request
    // read; this lifts the framework-level cap that runs before it.
    // A small headroom above chunk_size leaves room for HTTP overhead.
    let chunk_size = config.chunk_size();
    let limits = rocket::data::Limits::default()
        .limit("bytes", (chunk_size + 1024 * 1024).bytes())
        .limit("data-form", (chunk_size + 1024 * 1024).bytes())
        .limit("file", (chunk_size + 1024 * 1024).bytes());

    let rocket = rocket::custom(figment.merge(("limits", limits)));

    let cors = build_cors(AllowedOrigins::some_regex(&[config.allowed_origins()]));

    let metrics = Arc::new(Metrics::new());
    rocket::tokio::spawn(storage_sampler(
        metrics.clone(),
        std::path::PathBuf::from(config.data_dir()),
        Duration::from_secs(config.metrics_scan_interval_secs()),
    ));

    let pkg_client = PkgClient::new(config.pkg_url().to_string());

    rocket
        .attach(cors)
        .mount("/", api_routes())
        .attach(AdHoc::config::<CryptifyConfig>())
        .manage(Store::with_idle_ttl(
            std::time::Duration::from_secs(config.session_ttl_secs()),
            metrics.clone(),
            config.usage_db(),
            Path::new(config.data_dir()),
            config.rolling_window_secs(),
        ))
        .manage(vk)
        .manage(pkg_client)
        .manage(metrics)
}

/// Fetch the IBS verifying key from pg-pkg, retrying transient failures
/// (unreachable, non-2xx, unparsable body) with exponential backoff instead of
/// panicking on the first attempt: a brief PKG unavailability window — e.g. a
/// rolling deploy where cryptify comes up before pg-pkg — must not take
/// cryptify down with it. Returns `None` once the budget is exhausted.
async fn try_fetch_verifying_key(
    pkg_params_url: &str,
    budget: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> Option<Parameters<VerifyingKey>> {
    let deadline = rocket::tokio::time::Instant::now() + budget;
    let mut backoff = initial_backoff;

    loop {
        // minreq is blocking; keep it off the async workers.
        let url = pkg_params_url.to_owned();
        let result =
            rocket::tokio::task::spawn_blocking(move || minreq::get(&url).with_timeout(10).send())
                .await
                .expect("blocking fetch task panicked");

        match result {
            // minreq returns Ok for any completed HTTP exchange, so surface a
            // non-2xx (e.g. a 503 while the PKG is still booting) as a status
            // problem rather than a confusing parse failure.
            Ok(response) if !(200..300).contains(&response.status_code) => log::warn!(
                "PKG at {pkg_params_url} returned status {} — will retry",
                response.status_code
            ),
            Ok(response) => match response.json::<Parameters<VerifyingKey>>() {
                Ok(vk) => return Some(vk),
                Err(e) => log::warn!(
                    "Failed to parse verification key from {pkg_params_url}: {e} — will retry"
                ),
            },
            Err(e) => log::warn!("Failed to reach PKG at {pkg_params_url}: {e} — will retry"),
        }

        let now = rocket::tokio::time::Instant::now();
        if now + backoff >= deadline {
            return None;
        }
        rocket::tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

#[launch]
async fn rocket() -> _ {
    let figment = default_figment();
    let config = figment
        .extract::<CryptifyConfig>()
        .expect("Missing configuration");

    if config.metrics_token().is_none() {
        log::warn!(
            "metrics_token is not set — /metrics is publicly accessible without authentication. \
             Set `metrics_token` in config (or ROCKET_METRICS_TOKEN) to require a Bearer token."
        );
    }

    // A zero window makes every recorded upload expire immediately, which
    // switches the rolling quota off without any other symptom — on a path
    // whose init and chunk PUT take no credential. Loud at startup rather
    // than silent for the life of the deployment.
    if config.rolling_window_days() == 0 {
        log::warn!(
            "rolling_window_days is 0 — the rolling upload quota is effectively disabled, \
             since every recorded upload falls outside the window at once. Set a positive \
             value to enforce it."
        );
    }

    let pkg_params_url = format!(
        "{}/v2/sign/parameters",
        config.pkg_url().trim_end_matches('/')
    );
    let vk = try_fetch_verifying_key(
        &pkg_params_url,
        PKG_PARAMS_RETRY_BUDGET,
        PKG_PARAMS_INITIAL_BACKOFF,
        PKG_PARAMS_MAX_BACKOFF,
    )
    .await
    .unwrap_or_else(|| {
        panic!(
            "Could not fetch a valid verification key from {} within {:?}",
            pkg_params_url, PKG_PARAMS_RETRY_BUDGET
        )
    });

    build_rocket(figment, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::Client;

    // Test-only route exercising the FinalizeHeaders extractor in isolation.
    // Echoes the extracted fields so the test can verify successful parsing.
    #[post("/__test/finalize_headers")]
    fn finalize_headers_echo(h: FinalizeHeaders) -> String {
        format!("{}|{}", h.cryptify_token, h.content_range.size.unwrap_or(0))
    }

    async fn headers_client() -> Client {
        let r = rocket::build().mount("/", routes![finalize_headers_echo]);
        Client::tracked(r).await.expect("valid rocket")
    }

    #[rocket::async_test]
    async fn finalize_headers_reject_missing_cryptify_token() {
        let client = headers_client().await;
        let res = client
            .post("/__test/finalize_headers")
            .header(Header::new("Content-Range", "bytes 0-99/100"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::BadRequest);
    }

    #[rocket::async_test]
    async fn finalize_headers_reject_missing_content_range() {
        let client = headers_client().await;
        let res = client
            .post("/__test/finalize_headers")
            .header(Header::new("CryptifyToken", "abc123"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::BadRequest);
    }

    #[rocket::async_test]
    async fn finalize_headers_reject_malformed_content_range() {
        let client = headers_client().await;
        let res = client
            .post("/__test/finalize_headers")
            .header(Header::new("CryptifyToken", "abc123"))
            .header(Header::new("Content-Range", "not a real range"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::BadRequest);
    }

    #[rocket::async_test]
    async fn finalize_headers_extract_both_headers() {
        let client = headers_client().await;
        let res = client
            .post("/__test/finalize_headers")
            .header(Header::new("CryptifyToken", "deadbeef"))
            .header(Header::new("Content-Range", "bytes 0-99/100"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.into_string().await.as_deref(), Some("deadbeef|100"));
    }

    #[test]
    fn content_range_parses_well_formed_range() {
        let cr: ContentRange = "bytes 0-99/100".parse().unwrap();
        assert_eq!(cr.start, Some(0));
        assert_eq!(cr.end, Some(99));
        assert_eq!(cr.size, Some(100));
    }

    #[test]
    fn content_range_accepts_wildcard_range() {
        let cr: ContentRange = "bytes */100".parse().unwrap();
        assert_eq!(cr.start, None);
        assert_eq!(cr.end, None);
        assert_eq!(cr.size, Some(100));
    }

    #[test]
    fn content_range_accepts_wildcard_size() {
        let cr: ContentRange = "bytes 0-99/*".parse().unwrap();
        assert_eq!(cr.start, Some(0));
        assert_eq!(cr.end, Some(99));
        assert_eq!(cr.size, None);
    }

    #[test]
    fn content_range_rejects_wrong_unit() {
        assert!("items 0-99/100".parse::<ContentRange>().is_err());
    }

    #[test]
    fn content_range_rejects_empty_string() {
        assert!("".parse::<ContentRange>().is_err());
    }

    #[test]
    fn check_cryptify_token_accepts_matching_token() {
        assert!(check_cryptify_token("abc123", "abc123").is_ok());
    }

    #[test]
    fn check_cryptify_token_rejects_mismatched_token() {
        let result = check_cryptify_token("wrong", "expected");
        match result {
            Err(Error::BadRequest(Some(msg))) => {
                assert_eq!(msg, "Cryptify Token header does not match");
            }
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn check_cryptify_token_rejects_empty_header_when_token_expected() {
        assert!(matches!(
            check_cryptify_token("", "expected"),
            Err(Error::BadRequest(_))
        ));
    }

    #[test]
    fn check_cryptify_token_is_case_sensitive() {
        assert!(matches!(
            check_cryptify_token("ABC123", "abc123"),
            Err(Error::BadRequest(_))
        ));
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let h1 = compute_hash(b"token", b"data");
        let h2 = compute_hash(b"token", b"data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn compute_hash_differs_for_different_tokens() {
        assert_ne!(
            compute_hash(b"token-a", b"data"),
            compute_hash(b"token-b", b"data")
        );
    }

    #[test]
    fn cryptify_tokens_match_accepts_equal_and_rejects_different() {
        assert!(cryptify_tokens_match("abc123", "abc123"));
        assert!(!cryptify_tokens_match("abc123", "abc124"));
        // Differing lengths must not match (and must not panic).
        assert!(!cryptify_tokens_match("abc", "abc123"));
        assert!(!cryptify_tokens_match("", "abc"));
    }

    // Mounts only the `/usage` route with the state its guard depends on
    // (`CryptifyConfig` + `Store` + `PkgClient`). The `PkgClient` url is never
    // contacted for the unauthenticated case: `PkgClient::validate(None)`
    // short-circuits to `NoCredentials` before any network call.
    async fn usage_client() -> Client {
        use rocket::figment::{providers::Serialized, Figment};

        let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
            serde_json::json!({
                "server_url": "http://localhost",
                "data_dir": "/tmp",
                "email_from": "Test <test@example.com>",
                "smtp_url": "localhost",
                "smtp_port": 1025u16,
                "allowed_origins": ".*",
                "pkg_url": "http://localhost",
            }),
        ));

        let rocket = rocket::custom(figment)
            .mount("/", routes![usage])
            .attach(AdHoc::config::<CryptifyConfig>())
            .manage(Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60))
            .manage(PkgClient::new("http://localhost:1".to_string()));
        Client::tracked(rocket).await.expect("valid rocket")
    }

    // Regression test for GHSA-5rhx-xgvv-h78h: an unauthenticated caller (no
    // `Authorization: Bearer PG-…` header) must be rejected with 401 rather
    // than served usage for an arbitrary, caller-supplied email address.
    #[rocket::async_test]
    async fn usage_rejects_unauthenticated_request() {
        let client = usage_client().await;
        let res = client
            .get("/usage?email=alice@example.com")
            .dispatch()
            .await;
        assert_eq!(
            res.status(),
            Status::Unauthorized,
            "unauthenticated /usage must be 401, not a usage oracle for an arbitrary email"
        );
    }

    // Builds a minimal rocket instance that mounts only `upload_init` and the
    // state it depends on, with a fresh per-test `data_dir` under
    // `std::env::temp_dir()`. Used to verify upload_init's rejection path
    // does not leave orphan files behind (issue #125).
    async fn upload_init_client(data_dir: &std::path::Path) -> Client {
        use rocket::figment::{providers::Serialized, Figment};

        std::fs::create_dir_all(data_dir).expect("create test data_dir");

        let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
            serde_json::json!({
                "server_url": "http://localhost",
                "data_dir": data_dir.to_str().unwrap(),
                "email_from": "Test <test@example.com>",
                "smtp_url": "localhost",
                "smtp_port": 1025u16,
                "allowed_origins": ".*",
                "pkg_url": "http://localhost",
            }),
        ));

        let rocket = rocket::custom(figment)
            .mount("/", routes![upload_init])
            .attach(AdHoc::config::<CryptifyConfig>())
            .manage(Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60));

        Client::tracked(rocket).await.expect("valid rocket")
    }

    fn dir_entry_count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .map(|rd| rd.filter_map(Result::ok).count())
            .unwrap_or(0)
    }

    // Regression test for issue #125: a malformed recipient must not leave
    // an empty file behind in data_dir.
    #[rocket::async_test]
    async fn upload_init_bad_recipient_does_not_create_file() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = upload_init_client(&data_dir).await;

        assert_eq!(dir_entry_count(&data_dir), 0, "data_dir starts empty");

        let res = client
            .post("/fileupload/init")
            .header(rocket::http::ContentType::JSON)
            .body(
                r#"{"recipient":"not a valid address","mailContent":"hi","mailLang":"EN","confirm":false}"#,
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert_eq!(
            dir_entry_count(&data_dir),
            0,
            "no orphan file should be created when recipient parsing fails"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Happy-path complement: a valid recipient still creates exactly one file
    // in data_dir, so the reorder did not regress the success case.
    #[rocket::async_test]
    async fn upload_init_good_recipient_creates_file() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = upload_init_client(&data_dir).await;

        let res = client
            .post("/fileupload/init")
            .header(rocket::http::ContentType::JSON)
            .body(
                r#"{"recipient":"alice@example.com","mailContent":"hi","mailLang":"EN","confirm":false}"#,
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert_eq!(dir_entry_count(&data_dir), 1);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Builds a rocket instance with both upload_init and upload_status
    // mounted. Used for the cross-refresh-resume status-endpoint tests.
    async fn status_client(data_dir: &std::path::Path) -> Client {
        use rocket::figment::{providers::Serialized, Figment};

        std::fs::create_dir_all(data_dir).expect("create test data_dir");

        let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
            serde_json::json!({
                "server_url": "http://localhost",
                "data_dir": data_dir.to_str().unwrap(),
                "email_from": "Test <test@example.com>",
                "smtp_url": "localhost",
                "smtp_port": 1025u16,
                "allowed_origins": ".*",
                "pkg_url": "http://localhost",
            }),
        ));

        let rocket = rocket::custom(figment)
            .mount("/", routes![upload_init, upload_status])
            .attach(AdHoc::config::<CryptifyConfig>())
            .manage(Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60));

        Client::tracked(rocket).await.expect("valid rocket")
    }

    /// Variant of `status_client` that also attaches the production cors
    /// fairing, so tests can exercise browser-preflight behaviour for the
    /// new `/status` route.
    async fn status_client_with_cors(data_dir: &std::path::Path) -> Client {
        use rocket::figment::{providers::Serialized, Figment};

        std::fs::create_dir_all(data_dir).expect("create test data_dir");

        let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
            serde_json::json!({
                "server_url": "http://localhost",
                "data_dir": data_dir.to_str().unwrap(),
                "email_from": "Test <test@example.com>",
                "smtp_url": "localhost",
                "smtp_port": 1025u16,
                "allowed_origins": ".*",
                "pkg_url": "http://localhost",
            }),
        ));

        let cors = build_cors(AllowedOrigins::all());

        let rocket = rocket::custom(figment)
            .attach(cors)
            .mount("/", routes![upload_init, upload_status])
            .attach(AdHoc::config::<CryptifyConfig>())
            .manage(Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60));

        Client::tracked(rocket).await.expect("valid rocket")
    }

    /// Init an upload via the test client and return `(uuid, recovery_token)`.
    async fn init_upload(client: &Client) -> (String, String) {
        let res = client
            .post("/fileupload/init")
            .header(rocket::http::ContentType::JSON)
            .body(
                r#"{"recipient":"alice@example.com","mailContent":"hi","mailLang":"EN","confirm":false}"#,
            )
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);
        let body: serde_json::Value = res.into_json().await.expect("init body");
        let uuid = body["uuid"].as_str().expect("uuid in init body").to_owned();
        let recovery_token = body["recovery_token"]
            .as_str()
            .expect("recovery_token in init body")
            .to_owned();
        (uuid, recovery_token)
    }

    #[rocket::async_test]
    async fn status_returns_initial_state_after_init() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client(&data_dir).await;

        let (uuid, recovery_token) = init_upload(&client).await;

        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .header(Header::new("X-Recovery-Token", recovery_token))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);

        let body: serde_json::Value = res.into_json().await.expect("status body");
        assert_eq!(body["uploaded"].as_u64(), Some(0));
        assert!(body["cryptify_token"].as_str().is_some());
        // No chunk committed yet — prev_token / prev_offset are absent.
        assert!(body.get("prev_token").is_none());
        assert!(body.get("prev_offset").is_none());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn status_returns_401_when_recovery_header_missing() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client(&data_dir).await;

        let (uuid, _) = init_upload(&client).await;

        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Unauthorized);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn status_returns_401_when_recovery_header_blank() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client(&data_dir).await;

        let (uuid, _) = init_upload(&client).await;

        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .header(Header::new("X-Recovery-Token", "   "))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Unauthorized);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Wrong recovery token must return the same shape as an unknown UUID
    // — otherwise an attacker can probe for live UUIDs.
    #[rocket::async_test]
    async fn status_returns_404_for_token_mismatch_same_as_unknown_uuid() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client(&data_dir).await;

        let (uuid, _) = init_upload(&client).await;

        // Real UUID, wrong token.
        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .header(Header::new("X-Recovery-Token", "00".repeat(32)))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NotFound);
        let body_real: serde_json::Value = res.into_json().await.expect("404 body");
        assert_eq!(
            body_real["error"].as_str(),
            Some("upload_session_not_found")
        );

        // Unknown UUID, any token.
        let res = client
            .get(format!(
                "/fileupload/{}/status",
                uuid::Uuid::new_v4().hyphenated()
            ))
            .header(Header::new("X-Recovery-Token", "ff".repeat(32)))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NotFound);
        let body_fake: serde_json::Value = res.into_json().await.expect("404 body");
        assert_eq!(
            body_fake["error"].as_str(),
            Some("upload_session_not_found")
        );
        assert_eq!(body_real["error"], body_fake["error"]);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn constant_time_eq_helper() {
        // The function under test is the constant-time wrapper itself —
        // we can't observe timing in a unit test, but we can pin the
        // value-equality semantics so a future refactor doesn't silently
        // turn it into `presented == expected`.
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc12")); // length mismatch
        assert!(!constant_time_eq("", "abc"));
        assert!(constant_time_eq("", ""));
    }

    // Browser preflight regression: design AC for #146 explicitly required
    // a CORS smoke test so the `X-Recovery-Token` allow-list entry can't
    // silently regress. Sends an `OPTIONS /fileupload/{uuid}/status`
    // preflight and asserts the response advertises `X-Recovery-Token`
    // among `Access-Control-Allow-Headers`.
    #[rocket::async_test]
    async fn status_preflight_advertises_x_recovery_token() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client_with_cors(&data_dir).await;

        let res = client
            .req(
                rocket::http::Method::Options,
                "/fileupload/00000000-0000-0000-0000-000000000000/status",
            )
            .header(Header::new("Origin", "https://example.com"))
            .header(Header::new("Access-Control-Request-Method", "GET"))
            .header(Header::new(
                "Access-Control-Request-Headers",
                "X-Recovery-Token",
            ))
            .dispatch()
            .await;

        // rocket_cors echoes successful preflights back as 2xx.
        assert!(
            res.status().code < 400,
            "expected 2xx preflight, got {}",
            res.status()
        );
        let allow_headers = res
            .headers()
            .get_one("Access-Control-Allow-Headers")
            .expect("CORS allow-headers in preflight response");
        // Header names compare case-insensitively per RFC 7230, but the
        // standard cors fairing emits the names verbatim from our config.
        let allow_headers_lc = allow_headers.to_ascii_lowercase();
        assert!(
            allow_headers_lc.contains("x-recovery-token"),
            "Access-Control-Allow-Headers `{}` should include x-recovery-token",
            allow_headers
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Browser preflight regression: the website tags its uploads with
    // `X-Cryptify-Source` (postguard-website#228), which rides on every
    // pg-js request including `POST /fileupload/init`. If the header drops
    // out of the CORS allow-list, rocket_cors rejects the preflight with a
    // 403 that carries no `Access-Control-Allow-Origin`, and browsers
    // refuse the upload before it starts.
    #[rocket::async_test]
    async fn init_preflight_advertises_x_cryptify_source() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client_with_cors(&data_dir).await;

        let res = client
            .req(rocket::http::Method::Options, "/fileupload/init")
            .header(Header::new("Origin", "https://example.com"))
            .header(Header::new("Access-Control-Request-Method", "POST"))
            .header(Header::new(
                "Access-Control-Request-Headers",
                "Content-Type, X-Cryptify-Source",
            ))
            .dispatch()
            .await;

        assert!(
            res.status().code < 400,
            "expected 2xx preflight, got {}",
            res.status()
        );
        let allow_headers = res
            .headers()
            .get_one("Access-Control-Allow-Headers")
            .expect("CORS allow-headers in preflight response");
        let allow_headers_lc = allow_headers.to_ascii_lowercase();
        assert!(
            allow_headers_lc.contains("x-cryptify-source"),
            "Access-Control-Allow-Headers `{}` should include x-cryptify-source",
            allow_headers
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Browser preflight regression, the sibling of the two above. A browser
    // cannot send `X-PostGuard-Proof` on `POST /fileupload/finalize/{uuid}`
    // unless the CORS allow-list names it: rocket_cors answers the preflight
    // 403 with no `Access-Control-Allow-Origin`, so the header being optional
    // buys nothing and the upload fails before it starts. Nothing else holds
    // the entry in place, since the other tests are same-origin and the
    // `api-description.yaml` drift test compares routes, not headers.
    #[rocket::async_test]
    async fn finalize_preflight_advertises_x_postguard_proof() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client_with_cors(&data_dir).await;

        let res = client
            .req(
                rocket::http::Method::Options,
                "/fileupload/finalize/00000000-0000-0000-0000-000000000000",
            )
            .header(Header::new("Origin", "https://example.com"))
            .header(Header::new("Access-Control-Request-Method", "POST"))
            .header(Header::new(
                "Access-Control-Request-Headers",
                format!("CryptifyToken, {PROOF_HEADER}"),
            ))
            .dispatch()
            .await;

        assert!(
            res.status().code < 400,
            "expected 2xx preflight, got {}",
            res.status()
        );
        let allow_headers = res
            .headers()
            .get_one("Access-Control-Allow-Headers")
            .expect("CORS allow-headers in preflight response");
        let allow_headers_lc = allow_headers.to_ascii_lowercase();
        assert!(
            allow_headers_lc.contains(&PROOF_HEADER.to_ascii_lowercase()),
            "Access-Control-Allow-Headers `{}` should include {}",
            allow_headers,
            PROOF_HEADER
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Design AC for #146: a successful `/status` call must reset the idle
    // eviction deadline (otherwise rehydrate succeeds, then the very next
    // chunk PUT 404s because the session aged out between the GET and the
    // PUT). Inspect the deadline directly via the test-only accessor.
    #[rocket::async_test]
    async fn status_extends_eviction_deadline() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client(&data_dir).await;

        let (uuid, recovery_token) = init_upload(&client).await;

        let store = client.rocket().state::<Store>().expect("Store managed");
        let before = store
            .deadline_for(&uuid)
            .expect("session has a deadline after init");

        // tokio::time::Instant has millisecond resolution on most
        // platforms; sleep enough that a fresh `now() + ttl` is strictly
        // later than the value captured at init.
        rocket::tokio::time::sleep(Duration::from_millis(10)).await;

        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .header(Header::new("X-Recovery-Token", recovery_token))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);

        let after = store
            .deadline_for(&uuid)
            .expect("session still alive after status call");
        assert!(
            after > before,
            "successful /status should extend the eviction deadline"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Negative complement: failed auth (wrong recovery token) must NOT
    // extend the deadline. Otherwise an attacker with a known UUID could
    // keep a session alive past its eviction window just by hitting
    // `/status` with bogus tokens.
    #[rocket::async_test]
    async fn status_does_not_extend_deadline_on_token_mismatch() {
        let data_dir = std::env::temp_dir().join(format!(
            "cryptify-test-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let client = status_client(&data_dir).await;

        let (uuid, _) = init_upload(&client).await;

        let store = client.rocket().state::<Store>().expect("Store managed");
        let before = store
            .deadline_for(&uuid)
            .expect("session has a deadline after init");

        rocket::tokio::time::sleep(Duration::from_millis(10)).await;

        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .header(Header::new("X-Recovery-Token", "00".repeat(32)))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NotFound);

        let after = store
            .deadline_for(&uuid)
            .expect("session still alive (token mismatch doesn't evict)");
        assert_eq!(
            before, after,
            "failed-auth /status must not extend the deadline"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    fn empty_filestate(uploaded: u64, current_token: &str) -> FileState {
        FileState {
            uploaded,
            cryptify_token: current_token.to_owned(),
            expires: 0,
            recipients: lettre::message::Mailboxes::new(),
            mail_content: String::new(),
            mail_lang: email::Language::En,
            sender: None,
            sender_attributes: Vec::new(),
            confirm: false,
            source_channel: String::new(),
            client_version: None,
            client_app: None,
            notify_recipients: true,
            api_key_tenant: None,
            api_key_validation_failed: false,
            last_chunk: None,
            recovery_token_hash: String::new(),
            challenge: None,
            sender_claim: None,
        }
    }

    fn filestate_with_last_chunk(
        uploaded: u64,
        current_token: &str,
        last: LastChunkRecord,
    ) -> FileState {
        let mut s = empty_filestate(uploaded, current_token);
        s.last_chunk = Some(last);
        s
    }

    /// Build a `LastChunkRecord` whose `response_token` correctly encodes
    /// `prev_token + body`, the same construction the production handler
    /// uses. Tests use this so the replay path's hash check passes on a
    /// genuine retry and fails when the body is tampered with.
    fn last_chunk_for(prev_token: &str, prev_uploaded: u64, body: &[u8]) -> LastChunkRecord {
        LastChunkRecord {
            prev_token: prev_token.to_owned(),
            prev_uploaded,
            response_token: compute_hash(prev_token.as_bytes(), body),
        }
    }

    #[test]
    fn classify_normal_next_chunk() {
        let state = empty_filestate(100, "tok-current");
        match classify_chunk_request(&state, "tok-current", 100, b"chunk") {
            ChunkClassification::NormalNext => {}
            _ => panic!("expected NormalNext"),
        }
    }

    #[test]
    fn classify_replays_last_chunk_on_matching_retry() {
        let body = b"hello world";
        let last = last_chunk_for("tok-prev", 100, body);
        let response_token = last.response_token.clone();
        let state = filestate_with_last_chunk(100 + body.len() as u64, &response_token, last);
        match classify_chunk_request(&state, "tok-prev", 100, body) {
            ChunkClassification::ReplayLastChunk(t) => assert_eq!(t, response_token),
            _ => panic!("expected ReplayLastChunk"),
        }
    }

    #[test]
    fn classify_rejects_retry_with_different_body() {
        let body = b"original";
        let last = last_chunk_for("tok-prev", 100, body);
        let response_token = last.response_token.clone();
        let state = filestate_with_last_chunk(100 + body.len() as u64, &response_token, last);
        let tampered = b"tampered";
        let result = classify_chunk_request(&state, "tok-prev", 100, tampered);
        match result {
            ChunkClassification::Reject(Error::BadRequest(Some(msg))) => {
                assert!(msg.contains("body differs"), "got: {}", msg);
            }
            _ => panic!("expected BadRequest about body differs"),
        }
    }

    #[test]
    fn classify_rejects_retry_with_different_length() {
        // Same prev_token + start, but a shorter body. The recomputed
        // rolling hash won't match, so the body-differs path catches this
        // case too — we no longer need a length-specific record.
        let body = b"original";
        let last = last_chunk_for("tok-prev", 100, body);
        let response_token = last.response_token.clone();
        let state = filestate_with_last_chunk(100 + body.len() as u64, &response_token, last);
        let result = classify_chunk_request(&state, "tok-prev", 100, b"short");
        match result {
            ChunkClassification::Reject(Error::BadRequest(Some(msg))) => {
                assert!(msg.contains("body differs"), "got: {}", msg);
            }
            _ => panic!("expected BadRequest about body differs"),
        }
    }

    #[test]
    fn classify_rejects_offset_mismatch_with_no_replay() {
        // No last_chunk recorded → offset mismatch is just the regular 400.
        let state = empty_filestate(100, "tok-current");
        let result = classify_chunk_request(&state, "tok-current", 50, b"abc");
        match result {
            ChunkClassification::Reject(Error::BadRequest(Some(msg))) => {
                assert_eq!(msg, "Incorrect Content-Range header");
            }
            _ => panic!("expected BadRequest about Content-Range"),
        }
    }

    #[test]
    fn classify_rejects_token_mismatch_at_correct_offset() {
        let state = empty_filestate(100, "tok-current");
        let result = classify_chunk_request(&state, "tok-wrong", 100, b"chunk");
        match result {
            ChunkClassification::Reject(Error::BadRequest(Some(msg))) => {
                assert_eq!(msg, TOKEN_MISMATCH_MSG);
            }
            _ => panic!("expected BadRequest about token mismatch"),
        }
    }

    #[test]
    fn classify_does_not_replay_when_prev_token_does_not_match() {
        // Last chunk exists but the retry presents a *different* prev_token.
        // Falls through to the regular offset-mismatch rejection.
        let body = b"original";
        let last = last_chunk_for("tok-prev", 100, body);
        let response_token = last.response_token.clone();
        let state = filestate_with_last_chunk(100 + body.len() as u64, &response_token, last);
        let result = classify_chunk_request(&state, "tok-something-else", 100, body);
        match result {
            ChunkClassification::Reject(Error::BadRequest(Some(msg))) => {
                assert_eq!(msg, "Incorrect Content-Range header");
            }
            _ => panic!("expected BadRequest about Content-Range"),
        }
    }

    #[test]
    fn extract_pg_bearer_accepts_pg_prefixed_token() {
        assert_eq!(
            extract_pg_bearer(Some("Bearer PG-abc123")),
            Some("PG-abc123")
        );
    }

    #[test]
    fn extract_pg_bearer_accepts_lowercase_scheme() {
        assert_eq!(
            extract_pg_bearer(Some("bearer PG-abc123")),
            Some("PG-abc123")
        );
    }

    #[test]
    fn extract_pg_bearer_rejects_missing_header() {
        assert_eq!(extract_pg_bearer(None), None);
    }

    #[test]
    fn extract_pg_bearer_rejects_empty_header() {
        assert_eq!(extract_pg_bearer(Some("")), None);
    }

    #[test]
    fn extract_pg_bearer_rejects_non_pg_token() {
        // A JWT-style bearer must not be treated as a PG key.
        assert_eq!(
            extract_pg_bearer(Some("Bearer eyJhbGciOiJSUzI1NiJ9.foo.bar")),
            None
        );
    }

    #[test]
    fn extract_pg_bearer_rejects_wrong_scheme() {
        // `Basic` and other schemes must not pass through.
        assert_eq!(extract_pg_bearer(Some("Basic PG-abc")), None);
    }

    #[test]
    fn extract_pg_bearer_rejects_pg_prefix_without_scheme() {
        // The PG- prefix alone (no `Bearer `) is not a valid bearer.
        assert_eq!(extract_pg_bearer(Some("PG-abc123")), None);
    }

    // ----- Hex and proof decoding unit tests -----

    #[test]
    fn hex_round_trips_through_bytes_to_hex() {
        for bytes in [
            vec![],
            vec![0x00],
            vec![0xff, 0x00, 0x7f],
            (0u8..=255).collect(),
        ] {
            assert_eq!(hex_to_bytes(&bytes_to_hex(&bytes)), Some(bytes));
        }
    }

    #[test]
    fn hex_to_bytes_accepts_either_case() {
        assert_eq!(hex_to_bytes("DeadBEef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn hex_to_bytes_rejects_what_is_not_hex() {
        // An odd length, a non-hex digit, and a multi-byte character that a
        // `char`-indexed decoder would slice through the middle of.
        for input in ["abc", "zz", "ab cd", "aébc", "é"] {
            assert_eq!(hex_to_bytes(input), None, "{input:?} is not hex");
        }
    }

    #[test]
    fn decode_proof_rejects_values_that_are_not_a_signature() {
        use base64ct::{Base64, Encoding};

        assert!(decode_proof("not base64 ~~").is_none());
        // Well-formed base64 of the wrong length, both ways: a truncated
        // signature and a whole one with bytes hung off the end.
        let short = Base64::encode_string(&[0u8; pg_core::ibs::gg::SIG_BYTES - 1]);
        assert!(decode_proof(&short).is_none());
        let long = Base64::encode_string(&[0u8; pg_core::ibs::gg::SIG_BYTES + 1]);
        assert!(decode_proof(&long).is_none());
    }

    // ----- Range header parser unit tests -----

    #[test]
    fn parse_range_full() {
        let r = parse_range_header("bytes=0-99", 100).unwrap();
        assert_eq!(
            r,
            ByteRange {
                start: 0,
                end_inclusive: 99
            }
        );
        assert_eq!(r.len(), 100);
    }

    #[test]
    fn parse_range_open_end() {
        let r = parse_range_header("bytes=50-", 100).unwrap();
        assert_eq!(
            r,
            ByteRange {
                start: 50,
                end_inclusive: 99
            }
        );
    }

    #[test]
    fn parse_range_suffix() {
        let r = parse_range_header("bytes=-10", 100).unwrap();
        assert_eq!(
            r,
            ByteRange {
                start: 90,
                end_inclusive: 99
            }
        );
    }

    #[test]
    fn parse_range_suffix_larger_than_size_clamps() {
        let r = parse_range_header("bytes=-500", 100).unwrap();
        assert_eq!(
            r,
            ByteRange {
                start: 0,
                end_inclusive: 99
            }
        );
    }

    #[test]
    fn parse_range_end_past_size_clamps() {
        let r = parse_range_header("bytes=10-9999", 100).unwrap();
        assert_eq!(
            r,
            ByteRange {
                start: 10,
                end_inclusive: 99
            }
        );
    }

    #[test]
    fn parse_range_rejects_start_past_size() {
        assert!(parse_range_header("bytes=100-200", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_inverted() {
        assert!(parse_range_header("bytes=50-10", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_wrong_unit() {
        assert!(parse_range_header("items=0-9", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_multi_range() {
        // Multi-range is intentionally unsupported.
        assert!(parse_range_header("bytes=0-9,20-29", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_empty_suffix() {
        assert!(parse_range_header("bytes=-0", 100).is_none());
        assert!(parse_range_header("bytes=-", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_garbage() {
        assert!(parse_range_header("nonsense", 100).is_none());
        assert!(parse_range_header("bytes=abc-def", 100).is_none());
    }

    #[test]
    fn safe_segment_rejects_traversal_and_separators() {
        assert!(is_safe_download_segment("abc-123"));
        assert!(!is_safe_download_segment(""));
        assert!(!is_safe_download_segment(".."));
        assert!(!is_safe_download_segment("."));
        assert!(!is_safe_download_segment("a/b"));
        assert!(!is_safe_download_segment("a\\b"));
        assert!(!is_safe_download_segment("a\0b"));
    }

    // ----- /filedownload integration tests -----

    async fn download_client(data_dir: &std::path::Path) -> Client {
        use rocket::figment::{providers::Serialized, Figment};

        std::fs::create_dir_all(data_dir).expect("create test data_dir");

        let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
            serde_json::json!({
                "server_url": "http://localhost",
                "data_dir": data_dir.to_str().unwrap(),
                "email_from": "Test <test@example.com>",
                "smtp_url": "localhost",
                "smtp_port": 1025u16,
                "allowed_origins": ".*",
                "pkg_url": "http://localhost",
            }),
        ));

        let rocket = rocket::custom(figment)
            .mount("/", routes![download])
            .attach(AdHoc::config::<CryptifyConfig>());

        Client::tracked(rocket).await.expect("valid rocket")
    }

    fn fresh_data_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cryptify-dl-{}", uuid::Uuid::new_v4().hyphenated()))
    }

    #[rocket::async_test]
    async fn download_full_returns_200_with_accept_ranges() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;
        let body: Vec<u8> = (0u8..100).collect();
        std::fs::write(data_dir.join("file1"), &body).unwrap();

        let res = client.get("/filedownload/file1").dispatch().await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(
            res.headers().get_one("Accept-Ranges"),
            Some("bytes"),
            "Accept-Ranges must be advertised so browsers expose the resume button"
        );
        assert_eq!(res.headers().get_one("Content-Length"), Some("100"));
        let bytes = res.into_bytes().await.unwrap();
        assert_eq!(bytes, body);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn download_partial_returns_206_with_content_range() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;
        let body: Vec<u8> = (0u8..100).collect();
        std::fs::write(data_dir.join("file1"), &body).unwrap();

        let res = client
            .get("/filedownload/file1")
            .header(Header::new("Range", "bytes=10-19"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::PartialContent);
        assert_eq!(
            res.headers().get_one("Content-Range"),
            Some("bytes 10-19/100")
        );
        assert_eq!(res.headers().get_one("Content-Length"), Some("10"));
        assert_eq!(res.headers().get_one("Accept-Ranges"), Some("bytes"));
        let bytes = res.into_bytes().await.unwrap();
        assert_eq!(bytes, (10u8..20).collect::<Vec<u8>>());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn download_open_ended_range_resumes_from_offset() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;
        let body: Vec<u8> = (0u8..100).collect();
        std::fs::write(data_dir.join("file1"), &body).unwrap();

        let res = client
            .get("/filedownload/file1")
            .header(Header::new("Range", "bytes=80-"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::PartialContent);
        assert_eq!(
            res.headers().get_one("Content-Range"),
            Some("bytes 80-99/100")
        );
        let bytes = res.into_bytes().await.unwrap();
        assert_eq!(bytes, (80u8..100).collect::<Vec<u8>>());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn download_suffix_range_returns_tail() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;
        let body: Vec<u8> = (0u8..100).collect();
        std::fs::write(data_dir.join("file1"), &body).unwrap();

        let res = client
            .get("/filedownload/file1")
            .header(Header::new("Range", "bytes=-5"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::PartialContent);
        assert_eq!(
            res.headers().get_one("Content-Range"),
            Some("bytes 95-99/100")
        );
        let bytes = res.into_bytes().await.unwrap();
        assert_eq!(bytes, (95u8..100).collect::<Vec<u8>>());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn download_unsatisfiable_range_returns_416() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;
        let body: Vec<u8> = (0u8..100).collect();
        std::fs::write(data_dir.join("file1"), &body).unwrap();

        let res = client
            .get("/filedownload/file1")
            .header(Header::new("Range", "bytes=200-300"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::RangeNotSatisfiable);
        assert_eq!(res.headers().get_one("Content-Range"), Some("bytes */100"));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn download_missing_file_returns_404() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;

        let res = client.get("/filedownload/nope").dispatch().await;
        assert_eq!(res.status(), Status::NotFound);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[rocket::async_test]
    async fn download_rejects_path_traversal() {
        let data_dir = fresh_data_dir();
        let client = download_client(&data_dir).await;
        // Plant a "secret" file outside data_dir to make sure traversal
        // would actually leak something if the guard were bypassed.
        let secret_dir = data_dir.parent().unwrap().join(format!(
            "cryptify-dl-secret-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        std::fs::create_dir_all(&secret_dir).unwrap();
        let secret_path = secret_dir.join("secret");
        std::fs::write(&secret_path, b"do not leak").unwrap();

        // Rocket's router parses `<filename>` as a single URI segment, so
        // a literal `..` arrives as `..` and must be rejected by the guard.
        let res = client.get("/filedownload/..").dispatch().await;
        assert_eq!(res.status(), Status::NotFound);

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&secret_dir);
    }

    /// Build a minimal rocket exposing only the `staging_preview` route,
    /// with `staging_mode` controlled by the caller. The returned UUID
    /// (when `seed_uuid` is `Some`) is pre-inserted into the store so the
    /// happy-path test has something to render.
    async fn staging_preview_client(staging_mode: bool, seed_uuid: Option<&str>) -> Client {
        use rocket::figment::{providers::Serialized, Figment};

        let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
            serde_json::json!({
                "server_url": "https://staging.example.com",
                "data_dir": std::env::temp_dir().to_str().unwrap(),
                "email_from": "Test <noreply@example.com>",
                "smtp_url": "localhost",
                "smtp_port": 1025u16,
                "allowed_origins": ".*",
                "pkg_url": "http://localhost",
                "staging_mode": staging_mode,
            }),
        ));

        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
        if let Some(uuid) = seed_uuid {
            let mut mboxes = lettre::message::Mailboxes::new();
            mboxes.push("alice@example.com".parse().unwrap());
            mboxes.push("bob@example.com".parse().unwrap());
            let state = FileState {
                uploaded: 1234,
                cryptify_token: String::new(),
                expires: 1_700_000_000,
                recipients: mboxes,
                mail_content: String::new(),
                mail_lang: email::Language::En,
                sender: Some("sender@example.com".to_owned()),
                sender_attributes: Vec::new(),
                confirm: true,
                source_channel: String::new(),
                client_version: None,
                client_app: None,
                notify_recipients: true,
                api_key_tenant: None,
                api_key_validation_failed: false,
                last_chunk: None,
                recovery_token_hash: String::new(),
                challenge: None,
                sender_claim: None,
            };
            store.create(uuid.to_owned(), state);
        }

        let rocket = rocket::custom(figment)
            .mount("/", routes![staging_preview])
            .attach(AdHoc::config::<CryptifyConfig>())
            .manage(store);

        Client::tracked(rocket).await.expect("valid rocket")
    }

    #[rocket::async_test]
    async fn staging_preview_returns_404_in_production_mode() {
        let client = staging_preview_client(false, Some("uuid-known")).await;
        let res = client.get("/staging/preview/uuid-known").dispatch().await;
        assert_eq!(
            res.status(),
            Status::NotFound,
            "the staging_mode gate must hide the route in production"
        );
    }

    #[rocket::async_test]
    async fn staging_preview_returns_404_for_unknown_uuid() {
        let client = staging_preview_client(true, None).await;
        let res = client
            .get("/staging/preview/uuid-does-not-exist")
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NotFound);
    }

    #[rocket::async_test]
    async fn staging_preview_renders_recipients_and_confirmation() {
        let client = staging_preview_client(true, Some("uuid-known")).await;
        let res = client.get("/staging/preview/uuid-known").dispatch().await;
        assert_eq!(res.status(), Status::Ok);

        let body = res.into_string().await.expect("body");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        let recipients = v
            .get("recipients")
            .and_then(|r| r.as_array())
            .expect("recipients array");
        let emails: Vec<&str> = recipients
            .iter()
            .filter_map(|r| r.get("recipient").and_then(|s| s.as_str()))
            .collect();
        assert_eq!(emails, vec!["alice@example.com", "bob@example.com"]);
        for r in recipients {
            assert!(r.get("subject").and_then(|s| s.as_str()).is_some());
            assert!(r.get("html").and_then(|s| s.as_str()).is_some());
            assert!(r.get("text").and_then(|s| s.as_str()).is_some());
        }

        let confirmation = v.get("confirmation").expect("confirmation key present");
        assert_eq!(
            confirmation
                .get("recipient")
                .and_then(|s| s.as_str())
                .expect("confirmation.recipient"),
            "sender@example.com"
        );
    }
}

/// End-to-end integration tests for the upload pipeline
/// (`POST /fileupload/init` → `PUT /fileupload/<uuid>` →
/// `POST /fileupload/finalize/<uuid>`).
///
/// These tests boot a full Rocket instance via [`build_rocket`] with an
/// injected `VerifyingKey` from `pg_core::test::TestSetup`, so they exercise
/// the real extractors, state machine, token chain, and `Unsealer`-based
/// attribute extraction. SMTP is short-circuited by `staging_mode = true` so
/// the finalize happy-path does not require a live mail server.
#[cfg(test)]
mod integration {
    use super::*;
    use pg_core::client::rust::stream::SealerStreamConfig;
    use pg_core::client::Sealer;
    use pg_core::test::TestSetup;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::Client;

    // One of the test policies from `pg_core::test::TestSetup` includes
    // `pbdf.sidn-pbdf.email.email = "bob@example.com"`, and the encryption
    // policy seals for Bob & Charlie. Finalize's attribute extraction looks
    // for exactly this attribute type.
    const SENDER_EMAIL: &str = "bob@example.com";

    /// Build a figment that points at a freshly-created temp `data_dir` and
    /// disables outgoing email. Each test gets its own directory so they can
    /// run in parallel without clobbering each other's files.
    fn test_figment() -> (rocket::figment::Figment, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("cryptify-it-{}", uuid::Uuid::new_v4().hyphenated()));
        (test_figment_in(&dir), dir)
    }

    /// [`test_figment`] against a caller-supplied directory, so a test can
    /// build a second Rocket on the state the first one left behind.
    fn test_figment_in(dir: &std::path::Path) -> rocket::figment::Figment {
        std::fs::create_dir_all(dir).expect("create temp data_dir");

        let figment = default_figment()
            .merge(("server_url", "http://localhost:8000"))
            .merge(("data_dir", dir.to_string_lossy().to_string()))
            .merge(("email_from", "test@example.com"))
            .merge(("smtp_url", "localhost"))
            .merge(("smtp_port", 2525u16))
            .merge(("smtp_tls", false))
            .merge(("staging_mode", true))
            .merge(("allowed_origins", ".*"))
            .merge(("pkg_url", "http://localhost:8080"));

        figment
    }

    /// Seal `payload` for the encryption policy from `TestSetup`, producing a
    /// byte stream that `Unsealer` (and therefore `upload_finalize`) accepts.
    async fn seal_payload(setup: &TestSetup, payload: &[u8]) -> Vec<u8> {
        let mut rng = rand08::thread_rng();
        let signing_key = &setup.signing_keys[2]; // Bob: email + name
        let mut input = futures::io::Cursor::new(payload.to_vec());
        let mut sealed = Vec::new();
        Sealer::<_, SealerStreamConfig>::new(&setup.ibe_pk, &setup.policy, signing_key, &mut rng)
            .expect("build sealer")
            .seal(&mut input, &mut sealed)
            .await
            .expect("seal payload");
        sealed
    }

    /// Boot Rocket with the test figment and a verifying key from `TestSetup`.
    async fn test_client(setup: &TestSetup) -> (Client, std::path::PathBuf) {
        let (figment, dir) = test_figment();
        let vk = Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        };
        let rocket = build_rocket(figment, vk);
        let client = Client::tracked(rocket).await.expect("valid rocket");
        (client, dir)
    }

    /// Boot Rocket like [`test_client`] but with a caller-supplied
    /// `allowed_origins` regex, so CORS-preflight behaviour can be exercised
    /// against the exact regex shipped in `conf/config.toml`.
    async fn cors_client(setup: &TestSetup, allowed_origins: &str) -> (Client, std::path::PathBuf) {
        let (figment, dir) = test_figment();
        let figment = figment.merge(("allowed_origins", allowed_origins.to_string()));
        let vk = Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        };
        let rocket = build_rocket(figment, vk);
        let client = Client::tracked(rocket).await.expect("valid rocket");
        (client, dir)
    }

    /// Boot Rocket like [`test_client`] but with a caller-supplied
    /// `chunk_size`, so both the value `/fileupload/init` serves and the
    /// ceiling the chunk PUT enforces can be checked against something other
    /// than the 5 MB default.
    async fn chunk_size_client(setup: &TestSetup, chunk_size: u64) -> (Client, std::path::PathBuf) {
        let (figment, dir) = test_figment();
        let figment = figment.merge(("chunk_size", chunk_size));
        let vk = Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        };
        let rocket = build_rocket(figment, vk);
        let client = Client::tracked(rocket).await.expect("valid rocket");
        (client, dir)
    }

    /// Boot Rocket like [`test_client`] but with caller-supplied numeric
    /// config keys, so the limit checks can be driven without moving
    /// gigabytes.
    async fn limits_client(
        setup: &TestSetup,
        overrides: &[(&str, u64)],
    ) -> (Client, std::path::PathBuf) {
        let (figment, dir) = test_figment();
        let figment = overrides.iter().fold(figment, |figment, (key, value)| {
            figment.merge((*key, *value))
        });
        let vk = Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        };
        let client = Client::tracked(build_rocket(figment, vk))
            .await
            .expect("valid rocket");
        (client, dir)
    }

    /// `GET /limits`, optionally with an `Authorization` header, as status and
    /// raw body. Raw rather than parsed because the invariance test compares
    /// the bytes.
    async fn get_limits(client: &Client, authorization: Option<&str>) -> (Status, String) {
        let mut req = client.get("/limits");
        if let Some(value) = authorization {
            req = req.header(Header::new("Authorization", value.to_owned()));
        }
        let res = req.dispatch().await;
        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    fn limits_json(body: &str) -> serde_json::Value {
        serde_json::from_str(body).expect("/limits returns a JSON body")
    }

    // A copy of the production CORS regex from `conf/config.toml`, used to
    // assert the preflight shape (allowed origins, methods, headers) of the
    // regex we actually ship for the Office add-in (encryption4all/postguard#154).
    // This is a hand-maintained copy — the tests do NOT read `conf/config.toml`,
    // so keep the two in sync when either changes.
    const PROD_ALLOWED_ORIGINS: &str =
        r"^https://(postguard\.(eu|nl)|addin\.postguard\.eu|localhost:3000)$";

    #[rocket::async_test]
    async fn cors_preflight_allows_addin_and_localhost_origins() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = cors_client(&setup, PROD_ALLOWED_ORIGINS).await;

        for origin in ["https://addin.postguard.eu", "https://localhost:3000"] {
            let res = client
                .req(rocket::http::Method::Options, "/fileupload/init")
                .header(Header::new("Origin", origin))
                .header(Header::new("Access-Control-Request-Method", "POST"))
                .header(Header::new(
                    "Access-Control-Request-Headers",
                    "Content-Type, Authorization",
                ))
                .dispatch()
                .await;

            // rocket_cors answers a valid preflight with a 2xx.
            assert!(
                res.status().code < 400,
                "preflight from {origin} should succeed, got {}",
                res.status()
            );
            assert_eq!(
                res.headers().get_one("Access-Control-Allow-Origin"),
                Some(origin),
                "Allow-Origin should echo {origin}"
            );

            let allow_methods = res
                .headers()
                .get_one("Access-Control-Allow-Methods")
                .expect("Allow-Methods in preflight")
                .to_ascii_uppercase();
            for m in ["GET", "POST", "PUT", "DELETE"] {
                assert!(
                    allow_methods.contains(m),
                    "Allow-Methods `{allow_methods}` should include {m}"
                );
            }

            let allow_headers = res
                .headers()
                .get_one("Access-Control-Allow-Headers")
                .expect("Allow-Headers in preflight")
                .to_ascii_lowercase();
            for h in ["content-type", "authorization"] {
                assert!(
                    allow_headers.contains(h),
                    "Allow-Headers `{allow_headers}` should include {h}"
                );
            }
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn cors_preflight_rejects_unlisted_origin() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = cors_client(&setup, PROD_ALLOWED_ORIGINS).await;

        let res = client
            .req(rocket::http::Method::Options, "/fileupload/init")
            .header(Header::new("Origin", "https://evil.example.com"))
            .header(Header::new("Access-Control-Request-Method", "POST"))
            .dispatch()
            .await;

        // A non-matching origin must not be granted access: rocket_cors omits
        // the Allow-Origin header entirely for a rejected preflight.
        assert!(
            res.headers()
                .get_one("Access-Control-Allow-Origin")
                .is_none(),
            "unlisted origin must not receive an Access-Control-Allow-Origin header"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    fn init_body_json(recipient: &str) -> String {
        serde_json::json!({
            "recipient": recipient,
            "mailContent": "hello",
            "mailLang": "EN",
            "confirm": false,
        })
        .to_string()
    }

    async fn do_init(client: &Client, recipient: &str) -> (String, String, Status) {
        let res = client
            .post("/fileupload/init")
            .header(ContentType::JSON)
            .body(init_body_json(recipient))
            .dispatch()
            .await;
        let status = res.status();
        let token = res
            .headers()
            .get_one("cryptifytoken")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let body = res.into_string().await.unwrap_or_default();
        let uuid = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("uuid")
                    .and_then(|u| u.as_str().map(|s| s.to_string()))
            })
            .unwrap_or_default();
        (uuid, token, status)
    }

    /// PUT one chunk and return the response status, the advanced token and
    /// the raw body. The body is what the rejection paths are about; the token
    /// is what the success path needs, so both come back and the callers take
    /// what they came for.
    async fn chunk_response(
        client: &Client,
        uuid: &str,
        token: &str,
        chunk: &[u8],
        start: u64,
    ) -> (Status, String, String) {
        let end = start + chunk.len() as u64;
        let res = client
            .put(format!("/fileupload/{}", uuid))
            .header(Header::new("CryptifyToken", token.to_string()))
            .header(Header::new(
                "Content-Range",
                format!("bytes {}-{}/*", start, end),
            ))
            .body(chunk)
            .dispatch()
            .await;
        let status = res.status();
        let next = res
            .headers()
            .get_one("cryptifytoken")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let body = res.into_string().await.unwrap_or_default();
        (status, next, body)
    }

    /// PUT one chunk and return the response status plus the advanced token.
    async fn do_chunk(
        client: &Client,
        uuid: &str,
        token: &str,
        chunk: &[u8],
        start: u64,
    ) -> (Status, String) {
        let (status, next, _body) = chunk_response(client, uuid, token, chunk, start).await;
        (status, next)
    }

    /// Finalize and return the response status with its raw body.
    async fn finalize_response(
        client: &Client,
        uuid: &str,
        token: &str,
        total: u64,
    ) -> (Status, String) {
        let res = client
            .post(format!("/fileupload/finalize/{}", uuid))
            .header(Header::new("CryptifyToken", token.to_string()))
            .header(Header::new("Content-Range", format!("bytes */{}", total)))
            .dispatch()
            .await;
        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    async fn do_finalize(client: &Client, uuid: &str, token: &str, total: u64) -> Status {
        finalize_response(client, uuid, token, total).await.0
    }

    /// Boot Rocket through the same [`build_rocket`] seam as [`test_client`],
    /// but with `usage_db` pointed at a SQLite file inside the per-test
    /// `data_dir` — that key names cryptify's whole state database, so setting
    /// it is what turns upload-session persistence on. Returns the database
    /// path so a test can read the rows back with plain SQL, independent of
    /// the code that wrote them.
    async fn test_client_with_state_db(
        setup: &TestSetup,
    ) -> (Client, std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("cryptify-it-{}", uuid::Uuid::new_v4().hyphenated()));
        let client = boot_with_state_db(setup, &dir).await;
        let db_path = dir.join("state.db");
        (client, dir, db_path)
    }

    /// Boot Rocket on `dir` with the state database inside it — the same
    /// layout production uses (`usage_db` under the bind-mounted data
    /// directory). Calling it twice on one `dir` is what a restart looks like
    /// from the outside: the first instance is dropped, taking its `Store`
    /// and its SQLite connection with it, and the second finds only what
    /// reached disk.
    async fn boot_with_state_db(setup: &TestSetup, dir: &std::path::Path) -> Client {
        let db_path = dir.join("state.db");
        let figment =
            test_figment_in(dir).merge(("usage_db", db_path.to_string_lossy().to_string()));
        let vk = Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        };
        Client::tracked(build_rocket(figment, vk))
            .await
            .expect("valid rocket")
    }

    /// The columns an upload session's durable row must show after a
    /// transition, read straight out of SQLite.
    struct SessionRow {
        uploaded: i64,
        cryptify_token: String,
        prev_token: Option<String>,
        prev_uploaded: Option<i64>,
        recovery_token_hash: String,
        api_key_tenant: Option<String>,
        sender: Option<String>,
        created_at: i64,
        last_active_at: i64,
    }

    fn read_session_row(db_path: &std::path::Path, uuid: &str) -> Option<SessionRow> {
        let conn = rusqlite::Connection::open(db_path).expect("open state database");
        conn.query_row(
            "SELECT uploaded, cryptify_token, prev_token, prev_uploaded,
                    recovery_token_hash, api_key_tenant, sender, created_at, last_active_at
             FROM upload_sessions WHERE uuid = ?1",
            rusqlite::params![uuid],
            |row| {
                Ok(SessionRow {
                    uploaded: row.get(0)?,
                    cryptify_token: row.get(1)?,
                    prev_token: row.get(2)?,
                    prev_uploaded: row.get(3)?,
                    recovery_token_hash: row.get(4)?,
                    api_key_tenant: row.get(5)?,
                    sender: row.get(6)?,
                    created_at: row.get(7)?,
                    last_active_at: row.get(8)?,
                })
            },
        )
        .ok()
    }

    /// The done bar for postguard#302: after real HTTP init and chunk
    /// requests, the session is on disk in SQLite with the token the client
    /// was handed. Driven through the router, so it also proves the
    /// write-through actually runs inside the handlers — not just that
    /// `Store` can write a row when called directly.
    #[rocket::async_test]
    async fn session_rows_are_visible_in_sqlite_after_init_and_chunk() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir, db_path) = test_client_with_state_db(&setup).await;

        let (uuid, init_token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);

        let row = read_session_row(&db_path, &uuid).expect("init must persist a session row");
        assert_eq!(row.uploaded, 0);
        assert_eq!(
            row.cryptify_token, init_token,
            "the persisted token must be the one the client was told to use next"
        );
        assert_eq!(row.prev_token, None, "no chunk committed yet");
        assert_eq!(row.prev_uploaded, None);
        assert_eq!(row.sender, None, "sender is only known at finalize");
        assert_eq!(
            row.api_key_tenant, None,
            "this request presented no API key"
        );
        assert_eq!(
            row.recovery_token_hash.len(),
            64,
            "recovery token is stored as a hex SHA-256, never in the clear"
        );
        assert_eq!(row.created_at, row.last_active_at);

        let chunk = b"a chunk of sealed-looking bytes";
        let (chunk_status, next_token) = do_chunk(&client, &uuid, &init_token, chunk, 0).await;
        assert_eq!(chunk_status, Status::Ok);

        let row = read_session_row(&db_path, &uuid).expect("chunk must persist the session row");
        assert_eq!(row.uploaded, chunk.len() as i64);
        assert_eq!(
            row.cryptify_token, next_token,
            "the row must carry the advanced token the response returned"
        );
        assert_eq!(
            row.prev_token.as_deref(),
            Some(init_token.as_str()),
            "the replay record must persist so a restart can still accept a retry"
        );
        assert_eq!(row.prev_uploaded, Some(0));
        assert!(row.last_active_at >= row.created_at);

        // The client-visible surface is unchanged: nothing about persistence
        // is exposed on the responses, and the flow still completes.
        assert!(!next_token.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Finalize is the third transition, and the only one that learns the
    /// sender. Runs the whole flow against a real sealed payload.
    #[rocket::async_test]
    async fn finalize_persists_the_sender_to_sqlite() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"hello persistence").await;
        let (client, dir, db_path) = test_client_with_state_db(&setup).await;

        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let (chunk_status, token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);
        assert_eq!(
            do_finalize(&client, &uuid, &token, sealed.len() as u64).await,
            Status::Ok
        );

        let row = read_session_row(&db_path, &uuid).expect("row after finalize");
        assert_eq!(
            row.sender.as_deref(),
            Some(SENDER_EMAIL),
            "finalize must persist the sender it unsealed"
        );
        assert_eq!(row.uploaded, sealed.len() as i64);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Persistence must not change any client-visible behaviour, so the same
    /// happy path has to pass with the state database switched on.
    #[rocket::async_test]
    async fn upload_happy_path_is_unchanged_with_persistence_enabled() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"hello persistent integration test").await;
        let (client, dir, _db_path) = test_client_with_state_db(&setup).await;

        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let (chunk_status, token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);
        assert_eq!(
            do_finalize(&client, &uuid, &token, sealed.len() as u64).await,
            Status::Ok
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    // ---------------------------------------------------------------------
    // Restart recovery (postguard#303).
    //
    // Each of these drops the Rocket instance mid-upload and boots a second
    // one on the same `data_dir` and state database — the redeploy that used
    // to answer the next chunk PUT with a 404 (postguard-website#117).
    // ---------------------------------------------------------------------

    /// Like [`do_init`] but also returns the `recovery_token` from the body,
    /// which `GET /fileupload/{uuid}/status` requires.
    async fn do_init_with_recovery(client: &Client, recipient: &str) -> (String, String, String) {
        let res = client
            .post("/fileupload/init")
            .header(ContentType::JSON)
            .body(init_body_json(recipient))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);
        let token = res
            .headers()
            .get_one("cryptifytoken")
            .expect("cryptifytoken header")
            .to_owned();
        let body: serde_json::Value = res.into_json().await.expect("init body");
        (
            body["uuid"].as_str().expect("uuid").to_owned(),
            token,
            body["recovery_token"]
                .as_str()
                .expect("recovery_token")
                .to_owned(),
        )
    }

    async fn do_status(
        client: &Client,
        uuid: &str,
        recovery_token: &str,
    ) -> (Status, serde_json::Value) {
        let res = client
            .get(format!("/fileupload/{}/status", uuid))
            .header(Header::new("X-Recovery-Token", recovery_token.to_owned()))
            .dispatch()
            .await;
        let status = res.status();
        let body = res
            .into_json::<serde_json::Value>()
            .await
            .unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    /// The done bar for postguard#303: an upload survives the process that
    /// was serving it. Init and the first chunk go to one Rocket instance,
    /// the rest to a second one built on the same `data_dir` and database,
    /// and the file still unseals at finalize — so the restored session
    /// carried both the rolling token and the bytes already on disk.
    #[rocket::async_test]
    async fn an_upload_resumes_across_a_restart() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"a payload that outlives the process").await;
        let split = sealed.len() / 2;
        let dir =
            std::env::temp_dir().join(format!("cryptify-it-{}", uuid::Uuid::new_v4().hyphenated()));

        let (uuid, token) = {
            let client = boot_with_state_db(&setup, &dir).await;
            let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
            assert_eq!(status, Status::Ok);
            let (chunk_status, token) = do_chunk(&client, &uuid, &token, &sealed[..split], 0).await;
            assert_eq!(chunk_status, Status::Ok);
            (uuid, token)
            // The client — and with it the Store, its in-memory map and its
            // SQLite connection — is dropped here. Everything the second
            // instance knows has to come off disk.
        };

        let client = boot_with_state_db(&setup, &dir).await;

        let (chunk_status, token) =
            do_chunk(&client, &uuid, &token, &sealed[split..], split as u64).await;
        assert_eq!(
            chunk_status,
            Status::Ok,
            "the chunk after a restart must be accepted, not 404'd"
        );
        assert_eq!(
            do_finalize(&client, &uuid, &token, sealed.len() as u64).await,
            Status::Ok,
            "finalize must unseal a file written by two different processes"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A restored session holds only `sha256(recovery_token)`, so the status
    /// endpoint has to authenticate against the digest — and still refuse a
    /// wrong token the same way it refuses an unknown UUID.
    #[rocket::async_test]
    async fn the_status_endpoint_authenticates_a_restored_session() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let chunk = b"the first chunk, sent before the restart";
        let dir =
            std::env::temp_dir().join(format!("cryptify-it-{}", uuid::Uuid::new_v4().hyphenated()));

        let (uuid, token, recovery_token) = {
            let client = boot_with_state_db(&setup, &dir).await;
            let (uuid, token, recovery_token) = do_init_with_recovery(&client, SENDER_EMAIL).await;
            let (chunk_status, next) = do_chunk(&client, &uuid, &token, chunk, 0).await;
            assert_eq!(chunk_status, Status::Ok);
            (uuid, next, recovery_token)
        };

        let client = boot_with_state_db(&setup, &dir).await;

        let (status, body) = do_status(&client, &uuid, &recovery_token).await;
        assert_eq!(
            status,
            Status::Ok,
            "the token issued before the restart must still work"
        );
        assert_eq!(body["uploaded"].as_u64(), Some(chunk.len() as u64));
        assert_eq!(body["cryptify_token"].as_str(), Some(token.as_str()));
        assert_eq!(
            body["prev_offset"].as_u64(),
            Some(0),
            "the replay record has to come back too, or a rehydrating client cannot retry"
        );

        let (status, _) = do_status(&client, &uuid, &"0".repeat(64)).await;
        assert_eq!(
            status,
            Status::NotFound,
            "a wrong token stays indistinguishable from an unknown session"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The case the restart actually creates: the client never saw the
    /// response to its last chunk because the process went away, so it
    /// retries that chunk against the new one. It must be recognised as a
    /// replay — same token back, nothing written twice.
    #[rocket::async_test]
    async fn replaying_the_last_chunk_after_a_restart_is_idempotent() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"a chunk the client retries").await;
        let split = sealed.len() / 2;
        let dir =
            std::env::temp_dir().join(format!("cryptify-it-{}", uuid::Uuid::new_v4().hyphenated()));

        let (uuid, init_token, response_token, recovery_token) = {
            let client = boot_with_state_db(&setup, &dir).await;
            let (uuid, init_token, recovery_token) =
                do_init_with_recovery(&client, SENDER_EMAIL).await;
            let (chunk_status, response_token) =
                do_chunk(&client, &uuid, &init_token, &sealed[..split], 0).await;
            assert_eq!(chunk_status, Status::Ok);
            (uuid, init_token, response_token, recovery_token)
        };

        let client = boot_with_state_db(&setup, &dir).await;

        // Retry the first chunk with the token the client last held.
        let (replay_status, replayed) =
            do_chunk(&client, &uuid, &init_token, &sealed[..split], 0).await;
        assert_eq!(replay_status, Status::Ok, "a replay must not 400");
        assert_eq!(
            replayed, response_token,
            "the replay must return the original response token, not advance the chain"
        );

        let (_, body) = do_status(&client, &uuid, &recovery_token).await;
        assert_eq!(
            body["uploaded"].as_u64(),
            Some(split as u64),
            "a replayed chunk must not be counted twice"
        );

        // And the upload still completes from where it left off.
        let (chunk_status, token) =
            do_chunk(&client, &uuid, &replayed, &sealed[split..], split as u64).await;
        assert_eq!(chunk_status, Status::Ok);
        assert_eq!(
            do_finalize(&client, &uuid, &token, sealed.len() as u64).await,
            Status::Ok
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The other half of the ticket: a session that idled out while the
    /// process was down leaves neither a row nor the bytes it had written.
    #[rocket::async_test]
    async fn a_session_that_expired_while_down_is_cleaned_up() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let dir =
            std::env::temp_dir().join(format!("cryptify-it-{}", uuid::Uuid::new_v4().hyphenated()));
        let db_path = dir.join("state.db");

        let (uuid, token, recovery_token) = {
            let client = boot_with_state_db(&setup, &dir).await;
            let (uuid, token, recovery_token) = do_init_with_recovery(&client, SENDER_EMAIL).await;
            let (chunk_status, _) = do_chunk(&client, &uuid, &token, b"half an upload", 0).await;
            assert_eq!(chunk_status, Status::Ok);
            (uuid, token, recovery_token)
        };
        assert!(
            dir.join(&uuid).exists(),
            "the chunk was written to data_dir"
        );

        // Backdate the session past the idle window over a second connection,
        // the way a process that was down for an hour would leave it.
        let conn = rusqlite::Connection::open(&db_path).expect("open state database");
        let stale = chrono::offset::Utc::now().timestamp() - 7_200;
        conn.execute(
            "UPDATE upload_sessions SET last_active_at = ?2 WHERE uuid = ?1",
            rusqlite::params![uuid, stale],
        )
        .expect("backdate the session");
        drop(conn);

        let client = boot_with_state_db(&setup, &dir).await;

        assert!(
            !dir.join(&uuid).exists(),
            "the partial upload of an expired session must be swept from data_dir"
        );
        assert!(
            read_session_row(&db_path, &uuid).is_none(),
            "its row must go with it"
        );
        let (status, _) = do_status(&client, &uuid, &recovery_token).await;
        assert_eq!(status, Status::NotFound);
        let (chunk_status, _) = do_chunk(&client, &uuid, &token, b"more bytes", 14).await;
        assert_eq!(chunk_status, Status::NotFound);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// `max_chunk_size_bytes` on the init response and the ceiling the chunk
    /// PUT enforces are the same configured value, so a client that sizes its
    /// chunks from the served field is never rejected for being too large.
    ///
    /// The configured size is deliberately not the 5 MB default: against the
    /// default, a handler that served a hardcoded `5_000_000` would pass every
    /// assertion below and this test would guard nothing.
    #[rocket::async_test]
    async fn init_serves_the_configured_chunk_size_and_enforces_it() {
        const CONFIGURED_CHUNK_SIZE: u64 = 1_048_576;

        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = chunk_size_client(&setup, CONFIGURED_CHUNK_SIZE).await;

        // Init advertises the configured ceiling.
        let res = client
            .post("/fileupload/init")
            .header(ContentType::JSON)
            .body(init_body_json(SENDER_EMAIL))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);
        let token = res
            .headers()
            .get_one("cryptifytoken")
            .expect("cryptifytoken on init")
            .to_string();
        let body = res.into_string().await.expect("init body");
        let body: serde_json::Value = serde_json::from_str(&body).expect("init body is JSON");
        assert_eq!(
            body["max_chunk_size_bytes"].as_u64(),
            Some(CONFIGURED_CHUNK_SIZE),
            "init should serve the configured chunk size, got body {body}"
        );
        let uuid = body["uuid"]
            .as_str()
            .expect("uuid in init body")
            .to_string();

        // A chunk of exactly the advertised size is accepted.
        let at_limit = vec![0u8; CONFIGURED_CHUNK_SIZE as usize];
        let (status, _next) = do_chunk(&client, &uuid, &token, &at_limit, 0).await;
        assert_eq!(status, Status::Ok, "a chunk of exactly the advertised size");

        // One byte over is rejected. On a fresh session, so the offset and the
        // initial token are the ones this chunk is presented with.
        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let over_limit = vec![0u8; CONFIGURED_CHUNK_SIZE as usize + 1];
        let (status, _) = do_chunk(&client, &uuid, &token, &over_limit, 0).await;
        assert_eq!(
            status,
            Status::BadRequest,
            "a chunk one byte over the advertised size"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_happy_path_init_chunk_finalize() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"hello integration test").await;

        let (client, dir) = test_client(&setup).await;

        let (uuid, mut token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        assert!(!uuid.is_empty());
        assert!(!token.is_empty());

        // Upload in a single chunk (payload is well under CHUNK_SIZE).
        let (chunk_status, next) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);
        token = next;

        let final_status = do_finalize(&client, &uuid, &token, sealed.len() as u64).await;
        assert_eq!(final_status, Status::Ok);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Rewrite the sender spelling stored in a sealed container's public
    /// signing policy.
    ///
    /// pg-core's `Sealer` canonicalizes the signing policy before writing it,
    /// but that is a courtesy of the honest client, not a gate: `Unsealer::new`
    /// verifies the header signature against the identity *derived* from that
    /// policy, and `Policy::derive` canonicalizes, so a container storing any
    /// other spelling of the same address verifies just the same and hands
    /// cryptify the raw spelling as `pub_id`. This produces what a client that
    /// skips the courtesy uploads.
    ///
    /// The rewrite is a byte substitution confined to the header-signature
    /// block, so `replacement` must be as long as `original`: every length
    /// prefix in the stream then stays valid, and the header bytes the
    /// signature covers are left untouched.
    fn respell_stored_sender(sealed: &[u8], original: &str, replacement: &str) -> Vec<u8> {
        use pg_core::consts::{HEADER_SIZE_SIZE, PRELUDE_SIZE, SIG_SIZE_SIZE, VERSION_SIZE};

        assert_eq!(
            original.len(),
            replacement.len(),
            "the rewrite must not move any length prefix"
        );

        // PRELUDE | version | header len | header | signature len | signature | ...
        let header_len_at = PRELUDE_SIZE + VERSION_SIZE;
        let header_at = header_len_at + HEADER_SIZE_SIZE;
        let header_len = u32::from_be_bytes(
            sealed[header_len_at..header_at]
                .try_into()
                .expect("header length"),
        ) as usize;
        let sig_len_at = header_at + header_len;
        let sig_at = sig_len_at + SIG_SIZE_SIZE;
        let sig_len = u32::from_be_bytes(
            sealed[sig_len_at..sig_at]
                .try_into()
                .expect("signature length"),
        ) as usize;

        let block = &sealed[sig_at..sig_at + sig_len];
        let needle = original.as_bytes();
        let at = block
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the stored policy carries the sender address");
        assert!(
            block[at + needle.len()..]
                .windows(needle.len())
                .all(|w| w != needle),
            "the sender address must occur once in the signature block"
        );

        let mut out = sealed.to_vec();
        out[sig_at + at..sig_at + at + needle.len()].copy_from_slice(replacement.as_bytes());
        out
    }

    /// The sender email a container stores in its public signing policy, read
    /// back exactly the way `upload_finalize` reads it. Verifying the container
    /// is part of that read, so this doubles as the check that a respelled one
    /// is still accepted.
    async fn stored_sender(sealed: &[u8], setup: &TestSetup) -> Option<String> {
        let vk = VerifyingKey(setup.ibs_pk.0.clone());
        let mut cursor = futures::io::Cursor::new(sealed.to_vec());

        Unsealer::<_, UnsealerStreamConfig>::new(&mut cursor, &vk)
            .await
            .expect("the container must verify")
            .pub_id
            .con
            .into_iter()
            .find(|a| a.atype == "pbdf.sidn-pbdf.email.email")
            .and_then(|a| a.value)
    }

    /// init + one chunk + finalize, returning the finalize status.
    async fn upload_sealed(client: &Client, sealed: &[u8]) -> Status {
        let (uuid, token, status) = do_init(client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let (chunk_status, token) = do_chunk(client, &uuid, &token, sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);
        do_finalize(client, &uuid, &token, sealed.len() as u64).await
    }

    /// Two containers from one sender, spelled differently, must share a single
    /// rolling-limit bucket. Seed the bucket to leave room for exactly one
    /// container, let the capitalized upload take that room, and the lowercase
    /// one must then be refused. While the accounting key was the raw stored
    /// spelling these were two buckets and both went through.
    #[rocket::async_test]
    async fn two_spellings_of_one_sender_share_a_rolling_limit_bucket() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let canonical = seal_payload(&setup, b"one sender, two spellings").await;
        let capitalized = respell_stored_sender(&canonical, SENDER_EMAIL, "Bob@Example.COM");

        // The fixture is only worth something if cryptify really reads the new
        // spelling back, so pin that before the buckets are counted -- a byte
        // substitution that landed somewhere inert would leave this test
        // passing over a canonical container and guarding nothing.
        assert_eq!(
            stored_sender(&capitalized, &setup).await.as_deref(),
            Some("Bob@Example.COM"),
            "the container must present the capitalized spelling to finalize"
        );
        assert_eq!(
            stored_sender(&canonical, &setup).await.as_deref(),
            Some(SENDER_EMAIL)
        );

        let (client, dir) = test_client(&setup).await;
        let store = client.rocket().state::<Store>().expect("Store managed");
        // The limit the server is enforcing, read where the handler reads it,
        // so seeding the bucket to "room for exactly one container" cannot
        // drift from what the rolling check compares against.
        let rolling_limit = client
            .rocket()
            .state::<CryptifyConfig>()
            .expect("CryptifyConfig managed")
            .rolling_limit();

        let now = chrono::offset::Utc::now().timestamp();
        store.record_upload(
            SENDER_EMAIL.to_owned(),
            rolling_limit - capitalized.len() as u64,
            now,
        );

        assert_eq!(
            upload_sealed(&client, &capitalized).await,
            Status::Ok,
            "the first upload still fits inside the limit"
        );
        assert_eq!(
            store.get_usage(SENDER_EMAIL, now).used_bytes,
            rolling_limit,
            "the capitalized upload must accrue against the canonical bucket"
        );
        assert_eq!(
            upload_sealed(&client, &canonical).await,
            Status::PayloadTooLarge,
            "the second spelling must not get a bucket of its own"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The per-upload limit `GET /limits` serves is the one the chunk PUT
    /// enforces. Asserted against each other rather than against a literal:
    /// two numbers for one policy is the defect this route exists to remove,
    /// and only a comparison between them can catch it coming back.
    #[rocket::async_test]
    async fn served_per_upload_limit_is_the_enforced_one() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = limits_client(&setup, &[("per_upload_limit", 512)]).await;

        let (status, body) = get_limits(&client, None).await;
        assert_eq!(status, Status::Ok);
        let per_upload = limits_json(&body)["per_upload_limit_bytes"]
            .as_u64()
            .expect("per_upload_limit_bytes is a number");

        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let oversized = vec![0u8; per_upload as usize + 1];
        let (status, _token, body) = chunk_response(&client, &uuid, &token, &oversized, 0).await;

        assert_eq!(status, Status::PayloadTooLarge);
        let rejection: serde_json::Value =
            serde_json::from_str(&body).expect("the 413 carries a JSON body");
        assert_eq!(rejection["limit"].as_str(), Some("per_upload"));
        assert_eq!(
            rejection["limit_bytes"].as_u64(),
            Some(per_upload),
            "the limit the 413 names must be the one /limits served"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The same, against the rolling check at finalize.
    #[rocket::async_test]
    async fn served_rolling_limit_is_the_enforced_one() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"one byte over").await;
        let (client, dir) = limits_client(&setup, &[("rolling_limit", 4_096)]).await;

        let (status, body) = get_limits(&client, None).await;
        assert_eq!(status, Status::Ok);
        let rolling = limits_json(&body)["rolling_limit_bytes"]
            .as_u64()
            .expect("rolling_limit_bytes is a number");

        // Bucket seeded to exactly the limit, so any upload at all crosses it.
        let store = client.rocket().state::<Store>().expect("Store managed");
        let now = chrono::offset::Utc::now().timestamp();
        store.record_upload(SENDER_EMAIL.to_owned(), rolling, now);

        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let (status, token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(status, Status::Ok);
        let (status, body) = finalize_response(&client, &uuid, &token, sealed.len() as u64).await;

        assert_eq!(status, Status::PayloadTooLarge);
        let rejection: serde_json::Value =
            serde_json::from_str(&body).expect("the 413 carries a JSON body");
        assert_eq!(rejection["limit"].as_str(), Some("rolling_window"));
        assert_eq!(
            rejection["limit_bytes"].as_u64(),
            Some(rolling),
            "the limit the 413 names must be the one /limits served"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The rolling 413 must not carry the claimed sender's history: `used_bytes`
    /// is the rejected upload's own byte count, and `resets_at` is absent.
    /// Before postguard#387 both fields reported the claimed sender's
    /// rolling-window usage, an unauthenticated caller's own claim at
    /// finalize turning the 413 into a usage oracle for any address. Recorded
    /// usage is deliberately a different number from the rejected upload's
    /// size: if the two collided, a body that (wrongly) echoed the recorded
    /// usage back would pass the `used_bytes` assertion below vacuously.
    #[rocket::async_test]
    async fn rolling_413_does_not_carry_the_sender_history() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"the rejected upload's own bytes").await;
        let rolling_limit = sealed.len() as u64 + 10;
        let (client, dir) = limits_client(&setup, &[("rolling_limit", rolling_limit)]).await;

        let recorded_usage = rolling_limit - 1;
        assert_ne!(recorded_usage, sealed.len() as u64);

        let store = client.rocket().state::<Store>().expect("Store managed");
        let now = chrono::offset::Utc::now().timestamp();
        store.record_upload(SENDER_EMAIL.to_owned(), recorded_usage, now);

        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let (status, token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(status, Status::Ok);
        let (status, body) = finalize_response(&client, &uuid, &token, sealed.len() as u64).await;

        assert_eq!(status, Status::PayloadTooLarge);
        let rejection: serde_json::Value =
            serde_json::from_str(&body).expect("the 413 carries a JSON body");
        assert_eq!(rejection["limit"].as_str(), Some("rolling_window"));

        let mut keys: Vec<&str> = rejection
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["error", "limit", "limit_bytes", "used_bytes"],
            "the rolling 413 must carry no per-tenant history"
        );

        assert_eq!(
            rejection["used_bytes"].as_u64(),
            Some(sealed.len() as u64),
            "used_bytes must be the rejected upload's own size"
        );
        assert_ne!(
            rejection["used_bytes"].as_u64(),
            Some(recorded_usage),
            "used_bytes must not be the sender's recorded usage"
        );
        assert!(
            rejection.get("resets_at").is_none(),
            "resets_at must be absent from the rolling 413"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// `GET /limits` answers every caller with the same bytes.
    ///
    /// An endpoint whose contents depend on `Authorization` is how
    /// GHSA-5rhx-xgvv-h78h happened. The route takes no credential guard, so
    /// today it is structurally incapable of varying -- this is what goes red
    /// the day someone gives it one.
    #[rocket::async_test]
    async fn limits_are_byte_identical_for_every_caller() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let pkg_url = crate::email_template_tests::spawn_mock_pkg().await;

        let (figment, dir) = test_figment();
        let figment = figment.merge(("pkg_url", pkg_url));
        let vk = Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        };
        let client = Client::tracked(build_rocket(figment, vk))
            .await
            .expect("valid rocket");

        const KEY: &str = "Bearer PG-key-no-template";
        // The key has to be one the server really accepts, or the comparison
        // below is between two rejected callers and proves nothing.
        assert_eq!(
            client
                .get("/usage")
                .header(Header::new("Authorization", KEY))
                .dispatch()
                .await
                .status(),
            Status::Ok,
            "the mock pg-pkg must validate the key this test authenticates with"
        );

        let anonymous = get_limits(&client, None).await;
        let authenticated = get_limits(&client, Some(KEY)).await;
        assert_eq!(
            anonymous, authenticated,
            "/limits must not vary by Authorization, in status or in body"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// `/limits` reports the default tier and nothing per-tenant: the API-key
    /// tier's numbers belong to a caller who proved they hold the key, and
    /// `used_bytes`/`resets_at` stay behind `/usage`'s guard.
    #[rocket::async_test]
    async fn limits_serve_the_default_tier_only() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = limits_client(
            &setup,
            &[
                ("per_upload_limit", 111),
                ("rolling_limit", 222),
                ("api_key_per_upload_limit", 333),
                ("api_key_rolling_limit", 444),
            ],
        )
        .await;

        let (status, body) = get_limits(&client, None).await;
        assert_eq!(status, Status::Ok);
        let served = limits_json(&body);
        assert_eq!(served["per_upload_limit_bytes"].as_u64(), Some(111));
        assert_eq!(served["rolling_limit_bytes"].as_u64(), Some(222));

        let mut keys: Vec<&str> = served
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "per_upload_limit_bytes",
                "rolling_limit_bytes",
                "window_days"
            ],
            "/limits carries limits and nothing else"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A configured window has to reach both the number `/limits` serves and
    /// the expiry the store computes. One of the two moving without the other
    /// is the disagreement this ticket removes, one layer down.
    #[rocket::async_test]
    async fn a_configured_rolling_window_reaches_limits_and_the_store() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let window_days = 3u64;
        let (client, dir) = limits_client(&setup, &[("rolling_window_days", window_days)]).await;

        let (status, body) = get_limits(&client, None).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            limits_json(&body)["window_days"].as_u64(),
            Some(window_days)
        );

        let store = client.rocket().state::<Store>().expect("Store managed");
        let now = chrono::offset::Utc::now().timestamp();
        store.record_upload(SENDER_EMAIL.to_owned(), 1_000, now);
        assert_eq!(
            store.get_usage(SENDER_EMAIL, now).oldest_expires_at,
            Some(now + window_days as i64 * 24 * 60 * 60),
            "quota has to expire on the window /limits reports, not on the default"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The accounting key is a function of the *canonical* sender, never of the
    /// spelling the uploader chose. A regression here is silent -- every upload
    /// still succeeds -- so pin the property over a table rather than one case.
    #[test]
    fn accounting_key_canonicalizes_the_sender_spelling() {
        for atype in [
            "pbdf.sidn-pbdf.email.email",
            // Test deployments configure a test-scheme type (postguard#236);
            // the rule is keyed on the tail, so it applies there too.
            "irma-demo.sidn-pbdf.email.email",
        ] {
            for spelling in [
                "bob@example.com",
                "Bob@example.com",
                "bob@Example.COM",
                "BOB@EXAMPLE.COM",
                "  bob@example.com  ",
                "\tbob@example.com\n",
            ] {
                let key = accounting_key(None, atype, Some(spelling));
                assert_eq!(
                    key.as_deref(),
                    Some(SENDER_EMAIL),
                    "{atype} / {spelling:?} must not get a bucket of its own"
                );
                assert_eq!(
                    key,
                    Some(pg_core::identity::canonicalize(atype, spelling)),
                    "the accounting key must stay canonicalize() of the container value"
                );
            }
        }
    }

    /// A tenant id is not an identity attribute and has no rule, so it reaches
    /// the store as the API key named it -- and it still wins over the sender.
    #[test]
    fn accounting_key_leaves_the_api_key_tenant_alone() {
        assert_eq!(
            accounting_key(
                Some("Acme-EU"),
                "pbdf.sidn-pbdf.email.email",
                Some("Bob@Example.COM")
            )
            .as_deref(),
            Some("api-key:Acme-EU")
        );
    }

    /// No tenant and no sender is not accounted at all, as before.
    #[test]
    fn accounting_key_is_none_without_a_tenant_or_a_sender() {
        assert_eq!(
            accounting_key(None, "pbdf.sidn-pbdf.email.email", None),
            None
        );
    }

    // ---------------------------------------------------------------------
    // Upload proof (postguard#364).
    //
    // Driven through real HTTP requests end to end, so the challenge signed is
    // the one the client was handed, the proof travels in the header a client
    // sends, and the claim asserted on is the one finalize stored.
    // ---------------------------------------------------------------------

    /// The name attribute `TestSetup`'s Bob policy carries beside his email,
    /// and therefore the one attribute a proof of that identity claims.
    const SENDER_NAME_ATTRIBUTE: &str = "pbdf.gemeente.personalData.name";

    /// [`do_init`], also returning the `challenge` from the response body.
    async fn do_init_with_challenge(
        client: &Client,
        recipient: &str,
    ) -> (String, String, Option<String>) {
        let res = client
            .post("/fileupload/init")
            .header(ContentType::JSON)
            .body(init_body_json(recipient))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);
        let token = res
            .headers()
            .get_one("cryptifytoken")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let body = res.into_string().await.unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(&body).expect("init body is JSON");
        let field = |name: &str| {
            json.get(name)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        (field("uuid").expect("uuid"), token, field("challenge"))
    }

    /// The `X-PostGuard-Proof` value a client sends: `signChallenge` over the
    /// *decoded* challenge with the uuid as the context, serialized the way
    /// `pg-wasm` returns it, base64-encoded.
    fn proof_header(
        key: &pg_core::artifacts::SigningKeyExt,
        uuid: &str,
        challenge: &str,
    ) -> String {
        use base64ct::{Base64, Encoding};

        let mut rng = rand08::thread_rng();
        let challenge = hex_to_bytes(challenge).expect("the challenge is hex");
        let sig = pg_core::challenge::sign_challenge(key, uuid, &challenge, &mut rng);
        let bytes = pg_core::bincode_compat::serialize(&sig).expect("serialize the signature");

        Base64::encode_string(&bytes)
    }

    async fn do_finalize_with_proof(
        client: &Client,
        uuid: &str,
        token: &str,
        total: u64,
        proof: Option<&str>,
    ) -> Status {
        let mut req = client
            .post(format!("/fileupload/finalize/{}", uuid))
            .header(Header::new("CryptifyToken", token.to_string()))
            .header(Header::new("Content-Range", format!("bytes */{}", total)));
        if let Some(proof) = proof {
            req = req.header(Header::new(PROOF_HEADER, proof.to_string()));
        }

        req.dispatch().await.status()
    }

    /// init → one chunk → finalize, with the proof header `proof` builds from
    /// the uuid and challenge the server just minted. Returns the claim
    /// finalize settled on, and asserts along the way that the upload was
    /// accepted whatever the proof did — no proof outcome may refuse an
    /// upload in this ticket.
    async fn upload_with_proof(
        client: &Client,
        sealed: &[u8],
        proof: impl FnOnce(&str, &str) -> Option<String>,
    ) -> Option<SenderClaim> {
        let (uuid, token, challenge) = do_init_with_challenge(client, SENDER_EMAIL).await;
        let challenge = challenge.expect("init must serve a challenge");

        let (chunk_status, token) = do_chunk(client, &uuid, &token, sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);

        let header = proof(&uuid, &challenge);
        let status = do_finalize_with_proof(
            client,
            &uuid,
            &token,
            sealed.len() as u64,
            header.as_deref(),
        )
        .await;
        assert_eq!(
            status,
            Status::Ok,
            "a proof that fails or is absent must not refuse the upload"
        );

        let store = client.rocket().state::<Store>().expect("Store managed");
        let handle = store
            .get(&uuid)
            .expect("the session outlives a successful finalize");
        let claim = handle.lock().await.sender_claim.clone();

        claim
    }

    /// The client cannot answer a challenge it was not given, and two sessions
    /// must not share one — a reused challenge would let a proof collected for
    /// one upload be replayed onto another.
    #[rocket::async_test]
    async fn init_serves_a_fresh_challenge_and_stores_it() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;

        let (uuid, _token, challenge) = do_init_with_challenge(&client, SENDER_EMAIL).await;
        let challenge = challenge.expect("init must serve a challenge");
        assert_eq!(
            hex_to_bytes(&challenge).map(|bytes| bytes.len()),
            Some(32),
            "the challenge must decode to the 32 bytes the client signs"
        );

        let store = client.rocket().state::<Store>().expect("Store managed");
        let handle = store.get(&uuid).expect("live session");
        assert_eq!(
            handle.lock().await.challenge.as_deref(),
            Some(challenge.as_str()),
            "the session must hold the challenge the client was handed"
        );

        let (_, _, second) = do_init_with_challenge(&client, SENDER_EMAIL).await;
        assert_ne!(
            second.as_deref(),
            Some(challenge.as_str()),
            "each session must get its own challenge"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The done bar: a signature by the key belonging to the identity the
    /// container claims proves the sender, and the claim names that identity.
    #[rocket::async_test]
    async fn a_signed_challenge_proves_the_sender() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"an upload that proves its sender").await;
        let (client, dir) = test_client(&setup).await;

        // `seal_payload` signs the container with this key, so it is the one
        // the container's identity belongs to.
        let claim = upload_with_proof(&client, &sealed, |uuid, challenge| {
            Some(proof_header(&setup.signing_keys[2], uuid, challenge))
        })
        .await;

        assert_eq!(
            claim,
            Some(SenderClaim::Proven {
                email: SENDER_EMAIL.to_owned(),
                attrs: vec![(SENDER_NAME_ATTRIBUTE.to_owned(), "Bob".to_owned())],
            })
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A signature by a key for some *other* identity is the attack this whole
    /// ticket exists for: someone relaying a container they did not seal. It
    /// must not prove anything, and must not error either.
    #[rocket::async_test]
    async fn a_proof_from_another_identity_leaves_the_sender_unproven() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"a container someone else sealed").await;
        let (client, dir) = test_client(&setup).await;

        // Alice's key: a real, PKG-issued signing key for an identity that is
        // not the one the container claims.
        let claim = upload_with_proof(&client, &sealed, |uuid, challenge| {
            Some(proof_header(&setup.signing_keys[0], uuid, challenge))
        })
        .await;

        assert_eq!(claim, Some(SenderClaim::Unproven));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A signature over anything other than this session's challenge proves
    /// nothing — otherwise one proof, once collected, would answer forever.
    #[rocket::async_test]
    async fn a_proof_over_another_challenge_leaves_the_sender_unproven() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"a proof over the wrong challenge").await;
        let (client, dir) = test_client(&setup).await;

        let claim = upload_with_proof(&client, &sealed, |uuid, challenge| {
            let other = "00".repeat(32);
            assert_ne!(other, challenge, "the minted challenge is random");
            Some(proof_header(&setup.signing_keys[2], uuid, &other))
        })
        .await;

        assert_eq!(claim, Some(SenderClaim::Unproven));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The uuid is the context the proof is bound to, so a proof collected for
    /// one upload does not answer another's challenge even when the challenge
    /// bytes are somehow the same.
    #[rocket::async_test]
    async fn a_proof_bound_to_another_upload_leaves_the_sender_unproven() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"a proof bound to another upload").await;
        let (client, dir) = test_client(&setup).await;

        let claim = upload_with_proof(&client, &sealed, |uuid, challenge| {
            let other_uuid = uuid::Uuid::new_v4().hyphenated().to_string();
            assert_ne!(other_uuid, uuid);
            Some(proof_header(&setup.signing_keys[2], &other_uuid, challenge))
        })
        .await;

        assert_eq!(claim, Some(SenderClaim::Unproven));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The wire contract pins the standard base64 alphabet, so the same valid
    /// signature respelled in base64url proves nothing. Reaching for base64url
    /// is the reflex in web crypto code, and this is what makes the spec's
    /// claim about the alphabet load-bearing: the signature here verifies when
    /// spelled the documented way, so the alphabet is the only difference.
    #[rocket::async_test]
    async fn a_base64url_proof_leaves_the_sender_unproven() {
        use base64ct::{Base64, Base64Url, Encoding};

        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"a proof spelled in base64url").await;
        let (client, dir) = test_client(&setup).await;

        let claim = upload_with_proof(&client, &sealed, |uuid, challenge| {
            // A signature is 96 bytes, so its standard base64 is 128
            // characters, and roughly one in fifty of them happens to contain
            // neither `+` nor `/`. Then both alphabets spell it identically and
            // there is nothing left to test. Signing is randomised, so draw
            // again until the two spellings actually differ.
            let url = loop {
                let standard = proof_header(&setup.signing_keys[2], uuid, challenge);
                let bytes = Base64::decode_vec(&standard).expect("the header is standard base64");
                let url = Base64Url::encode_string(&bytes);
                if url != standard {
                    break url;
                }
            };
            Some(url)
        })
        .await;

        assert_eq!(claim, Some(SenderClaim::Unproven));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// No header at all is the state of every client that has not shipped the
    /// proof yet: unproven, and uploading exactly as before.
    #[rocket::async_test]
    async fn no_proof_header_leaves_the_sender_unproven() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"an upload from a client without the header").await;
        let (client, dir) = test_client(&setup).await;

        let claim = upload_with_proof(&client, &sealed, |_uuid, _challenge| None).await;

        assert_eq!(claim, Some(SenderClaim::Unproven));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A header that is not a signature at all is a failed proof, not a
    /// malformed request: same arm, same 200.
    #[rocket::async_test]
    async fn a_malformed_proof_header_leaves_the_sender_unproven() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"an upload with a junk proof").await;
        let (client, dir) = test_client(&setup).await;

        for junk in ["", "not base64 ~~", "AAAA"] {
            let claim =
                upload_with_proof(&client, &sealed, |_uuid, _challenge| Some(junk.to_owned()))
                    .await;
            assert_eq!(claim, Some(SenderClaim::Unproven), "{junk:?}");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A finalize can be repeated: the client retries after a lost response,
    /// or resumes after a refresh, in which case it no longer holds the
    /// challenge and cannot rebuild the header at all. Neither may erase a
    /// proof that already succeeded, and the unproven-to-proven direction
    /// must still work.
    #[rocket::async_test]
    async fn a_retried_finalize_does_not_erase_a_proof() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"an upload finalized twice").await;
        let (client, dir) = test_client(&setup).await;

        let claim_after = |uuid: String| {
            let store = client.rocket().state::<Store>().expect("Store managed");
            let handle = store
                .get(&uuid)
                .expect("the session outlives a successful finalize");
            async move { handle.lock().await.sender_claim.clone() }
        };

        // Proven first, then a retry with no header: the claim must stick.
        let (uuid, token, challenge) = do_init_with_challenge(&client, SENDER_EMAIL).await;
        let challenge = challenge.expect("init must serve a challenge");
        let (chunk_status, token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);
        let total = sealed.len() as u64;
        let proof = proof_header(&setup.signing_keys[2], &uuid, &challenge);

        let status = do_finalize_with_proof(&client, &uuid, &token, total, Some(&proof)).await;
        assert_eq!(status, Status::Ok);
        let proven = Some(SenderClaim::Proven {
            email: SENDER_EMAIL.to_owned(),
            attrs: vec![(SENDER_NAME_ATTRIBUTE.to_owned(), "Bob".to_owned())],
        });
        assert_eq!(
            claim_after(uuid.clone()).await,
            proven,
            "the first finalize proves the sender"
        );

        let status = do_finalize_with_proof(&client, &uuid, &token, total, None).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            claim_after(uuid.clone()).await,
            proven,
            "a retried finalize without the header must not downgrade a Proven claim"
        );

        // Unproven first, then a finalize that answers: the claim must upgrade.
        let (uuid, token, challenge) = do_init_with_challenge(&client, SENDER_EMAIL).await;
        let challenge = challenge.expect("init must serve a challenge");
        let (chunk_status, token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);

        let status = do_finalize_with_proof(&client, &uuid, &token, total, None).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            claim_after(uuid.clone()).await,
            Some(SenderClaim::Unproven),
            "no header leaves the sender unproven"
        );

        let proof = proof_header(&setup.signing_keys[2], &uuid, &challenge);
        let status = do_finalize_with_proof(&client, &uuid, &token, total, Some(&proof)).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            claim_after(uuid).await,
            proven,
            "a later finalize carrying a valid proof must still prove the sender"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Finalizing a session whose bytes are not a valid postguard stream makes
    /// the `Unsealer` fail, driving `upload_finalize` down its 500 path. The
    /// response body must carry only the generic message — never the internal
    /// diagnostic detail, which now goes to the server log (GHSA-r95f-qf3j-xccw).
    #[rocket::async_test]
    async fn finalize_internal_error_body_is_generic() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;

        // Upload arbitrary bytes: the chunk path only advances the rolling
        // token, it does not validate the postguard framing.
        let garbage = b"this is not a postguard sealed stream";
        let (uuid, token, status) = do_init(&client, SENDER_EMAIL).await;
        assert_eq!(status, Status::Ok);
        let (chunk_status, next) = do_chunk(&client, &uuid, &token, garbage, 0).await;
        assert_eq!(chunk_status, Status::Ok);

        let res = client
            .post(format!("/fileupload/finalize/{}", uuid))
            .header(Header::new("CryptifyToken", next))
            .header(Header::new(
                "Content-Range",
                format!("bytes */{}", garbage.len()),
            ))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::InternalServerError);
        let body = res.into_string().await.unwrap_or_default();
        assert_eq!(body, GENERIC_INTERNAL_ERROR_MSG);
        // Guard against re-introducing the old leaky diagnostics.
        assert!(
            !body.contains("postguard") && !body.contains("file"),
            "500 body must not leak internal detail, got: {body}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_records_client_app_metric() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"hello metric test").await;

        let (client, dir) = test_client(&setup).await;

        // Init carrying a client-version header whose `app` field is pg-js.
        let res = client
            .post("/fileupload/init")
            .header(ContentType::JSON)
            .header(Header::new(
                "X-POSTGUARD-CLIENT-VERSION",
                "node,22.1.0,pg-js,1.2.3",
            ))
            .body(init_body_json(SENDER_EMAIL))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);
        let mut token = res
            .headers()
            .get_one("cryptifytoken")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let body = res.into_string().await.unwrap_or_default();
        let uuid = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("uuid").and_then(|u| u.as_str().map(String::from)))
            .unwrap_or_default();
        assert!(!uuid.is_empty());

        let (chunk_status, next) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert_eq!(chunk_status, Status::Ok);
        token = next;

        let final_status = do_finalize(&client, &uuid, &token, sealed.len() as u64).await;
        assert_eq!(final_status, Status::Ok);

        // The finalized upload is attributed to app="pg-js".
        let metrics = client
            .get("/metrics")
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap_or_default();
        assert!(
            metrics.contains("cryptify_uploads_by_app_total{app=\"pg-js\"} 1"),
            "expected pg-js app counter in metrics:\n{metrics}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    // Minimal Rocket exposing only /metrics, with the given config managed so
    // the MetricsAuth guard can read `metrics_token`. Avoids needing a real
    // VerifyingKey / TestSetup.
    fn metrics_only_config(with_token: bool) -> CryptifyConfig {
        let (figment, _dir) = test_figment();
        let figment = if with_token {
            figment.merge(("metrics_token", "s3cret"))
        } else {
            figment
        };
        figment.extract::<CryptifyConfig>().expect("extract config")
    }

    async fn metrics_only_client(config: CryptifyConfig) -> Client {
        let rocket = rocket::build()
            .mount("/", routes![metrics_endpoint])
            .manage(config)
            .manage(std::sync::Arc::new(Metrics::new()));
        Client::tracked(rocket).await.expect("valid rocket")
    }

    #[rocket::async_test]
    async fn metrics_requires_bearer_when_token_configured() {
        let client = metrics_only_client(metrics_only_config(true)).await;

        // No Authorization header → 401.
        assert_eq!(
            client.get("/metrics").dispatch().await.status(),
            Status::Unauthorized
        );
        // Wrong token → 401.
        assert_eq!(
            client
                .get("/metrics")
                .header(Header::new("Authorization", "Bearer wrong"))
                .dispatch()
                .await
                .status(),
            Status::Unauthorized
        );
        // Correct token → 200 with the metrics body.
        let ok = client
            .get("/metrics")
            .header(Header::new("Authorization", "Bearer s3cret"))
            .dispatch()
            .await;
        assert_eq!(ok.status(), Status::Ok);
        assert!(ok
            .into_string()
            .await
            .unwrap_or_default()
            .contains("cryptify_uploads_total"));
    }

    #[rocket::async_test]
    async fn metrics_open_when_token_unset() {
        let client = metrics_only_client(metrics_only_config(false)).await;
        assert_eq!(client.get("/metrics").dispatch().await.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn upload_happy_path_multi_chunk() {
        // Two chunks >1 MiB to exercise the rolling token chain across
        // multiple PUTs. Keeps payload well under CHUNK_SIZE.
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let payload: Vec<u8> = (0..(2 * 1024 * 1024 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        let sealed = seal_payload(&setup, &payload).await;

        let (client, dir) = test_client(&setup).await;

        let (uuid, mut token, _) = do_init(&client, SENDER_EMAIL).await;

        let split = sealed.len() / 2;
        let (s1, next1) = do_chunk(&client, &uuid, &token, &sealed[..split], 0).await;
        assert_eq!(s1, Status::Ok);
        token = next1;

        let (s2, next2) = do_chunk(&client, &uuid, &token, &sealed[split..], split as u64).await;
        assert_eq!(s2, Status::Ok);
        token = next2;

        let final_status = do_finalize(&client, &uuid, &token, sealed.len() as u64).await;
        assert_eq!(final_status, Status::Ok);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_init_rejects_invalid_email() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;

        let res = client
            .post("/fileupload/init")
            .header(ContentType::JSON)
            .body(init_body_json("not-a-valid-email"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::BadRequest);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_chunk_rejects_wrong_cryptify_token() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;
        let (uuid, _token, _) = do_init(&client, SENDER_EMAIL).await;

        let (status, _) = do_chunk(&client, &uuid, "bogus-token", b"xxxx", 0).await;
        assert_eq!(status, Status::BadRequest);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_chunk_unknown_uuid_returns_404() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;

        let fake = uuid::Uuid::new_v4().hyphenated().to_string();
        let (status, _) = do_chunk(&client, &fake, "any-token", b"xxxx", 0).await;
        assert_eq!(status, Status::NotFound);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_chunk_invalid_uuid_reports_invalid_uuid_reason() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;

        let res = client
            .put("/fileupload/not-a-uuid")
            .header(Header::new("CryptifyToken", "any-token"))
            .header(Header::new("Content-Range", "bytes 0-4/*"))
            .body(b"xxxx" as &[u8])
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NotFound);
        let body = res.into_string().await.unwrap_or_default();
        assert!(
            body.contains("\"reason\":\"invalid_uuid\""),
            "expected invalid_uuid reason, got: {body}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_finalize_rejects_wrong_cryptify_token() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"hello").await;
        let (client, dir) = test_client(&setup).await;

        let (uuid, token, _) = do_init(&client, SENDER_EMAIL).await;
        let (_, new_token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;
        assert!(!new_token.is_empty());

        // Finalize with a bogus token — must be rejected before Unsealer runs.
        let status = do_finalize(&client, &uuid, "not-the-token", sealed.len() as u64).await;
        assert_eq!(status, Status::BadRequest);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_finalize_rejects_size_mismatch() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let sealed = seal_payload(&setup, b"hello").await;
        let (client, dir) = test_client(&setup).await;

        let (uuid, token, _) = do_init(&client, SENDER_EMAIL).await;
        let (_, new_token) = do_chunk(&client, &uuid, &token, &sealed, 0).await;

        // Claim the wrong total size in Content-Range.
        let wrong_total = (sealed.len() as u64).saturating_sub(1);
        let status = do_finalize(&client, &uuid, &new_token, wrong_total).await;
        assert_eq!(status, Status::UnprocessableEntity);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_finalize_unknown_uuid_returns_404() {
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;

        let fake = uuid::Uuid::new_v4().hyphenated().to_string();
        let status = do_finalize(&client, &fake, "any-token", 0).await;
        assert_eq!(status, Status::NotFound);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[rocket::async_test]
    async fn upload_chunk_rejects_content_range_misalignment() {
        // Start must equal state.uploaded (currently 0).
        let mut rng = rand08::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let (client, dir) = test_client(&setup).await;
        let (uuid, token, _) = do_init(&client, SENDER_EMAIL).await;

        let (status, _) = do_chunk(&client, &uuid, &token, b"xxxx", 100).await;
        assert_eq!(status, Status::BadRequest);

        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Tests for `GET /email-template` (issue #54). Covers both the pure
/// branch-mapping helper and the full route through the production
/// `ApiKey` request guard, exercised against a mock pg-pkg server so the
/// real validation flow (reqwest → `/v2/api-key/validate`) is on the path.
#[cfg(test)]
mod email_template_tests {
    use super::*;
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::Client;
    use std::time::Duration;

    // ----- Pure unit tests for the branch-mapping helper -----

    #[test]
    fn resolve_returns_template_for_validated_key_with_template() {
        let api_key = ApiKey {
            tenant: Some("tenant-123".to_owned()),
            validation_failed: false,
            email_template: Some("Hello {{name}}".to_owned()),
        };
        let resp = resolve_email_template(api_key).expect("validated key with template resolves");
        assert_eq!(resp.tenant_id, "tenant-123");
        assert_eq!(resp.email_template, "Hello {{name}}");
    }

    #[test]
    fn resolve_returns_404_for_validated_key_without_template() {
        let api_key = ApiKey {
            tenant: Some("tenant-123".to_owned()),
            validation_failed: false,
            email_template: None,
        };
        match resolve_email_template(api_key) {
            Err(Error::NotFound(_)) => {}
            _ => panic!("expected NotFound for a valid key with no template"),
        }
    }

    #[test]
    fn resolve_returns_401_for_missing_or_invalid_key() {
        let api_key = ApiKey {
            tenant: None,
            validation_failed: false,
            email_template: None,
        };
        match resolve_email_template(api_key) {
            Err(Error::Unauthorized(_)) => {}
            _ => panic!("expected Unauthorized when no tenant resolved"),
        }
    }

    #[test]
    fn resolve_returns_503_when_pkg_unreachable() {
        let api_key = ApiKey {
            tenant: None,
            validation_failed: true,
            email_template: None,
        };
        match resolve_email_template(api_key) {
            Err(Error::ServiceUnavailable(_)) => {}
            _ => panic!("expected ServiceUnavailable when pg-pkg was unreachable"),
        }
    }

    // ----- End-to-end tests through the real ApiKey guard -----

    /// Authorization-header capture for the mock pg-pkg route.
    struct MockAuth(Option<String>);

    #[rocket::async_trait]
    impl<'r> FromRequest<'r> for MockAuth {
        type Error = std::convert::Infallible;
        async fn from_request(
            req: &'r rocket::Request<'_>,
        ) -> rocket::request::Outcome<Self, Self::Error> {
            rocket::request::Outcome::Success(MockAuth(
                req.headers().get_one("Authorization").map(str::to_owned),
            ))
        }
    }

    /// Stand-in for pg-pkg's `GET /v2/api-key/validate`. Mirrors the
    /// authoritative responses the real `PkgClient` distinguishes:
    /// 200 + tenant (optionally with `email_template`) for a recognised
    /// key, 401 for anything else.
    #[get("/v2/api-key/validate")]
    fn mock_validate(auth: MockAuth) -> Result<Json<serde_json::Value>, Status> {
        match auth.0.as_deref() {
            Some("Bearer PG-key-with-template") => Ok(Json(serde_json::json!({
                "tenant_id": "tenant-abc",
                "organisation_name": "Acme",
                "email_template": "Beste {{naam}}, u heeft bestanden ontvangen."
            }))),
            Some("Bearer PG-key-no-template") => Ok(Json(serde_json::json!({
                "tenant_id": "tenant-xyz"
            }))),
            _ => Err(Status::Unauthorized),
        }
    }

    /// Launch the mock pg-pkg on a real ephemeral port and return its base
    /// URL. A real listener is required because the `ApiKey` guard reaches
    /// it via reqwest over TCP, not Rocket's in-process local client.
    pub(crate) async fn spawn_mock_pkg() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let figment = rocket::Config::figment()
            .merge(("port", port))
            .merge(("address", "127.0.0.1"))
            .merge(("log_level", "off"));
        let rocket = rocket::custom(figment).mount("/", routes![mock_validate]);
        rocket::tokio::spawn(async move {
            let _ = rocket.launch().await;
        });

        // Wait until the listener accepts connections so the first guard
        // call doesn't race startup. The PkgClient retry budget would cover
        // it anyway, but readiness keeps the test fast and quiet.
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            rocket::tokio::time::sleep(Duration::from_millis(10)).await;
        }
        format!("http://127.0.0.1:{}", port)
    }

    /// Cryptify client mounting only `/email-template`, with a `PkgClient`
    /// pointed at `pkg_url`.
    async fn email_template_client(pkg_url: String) -> Client {
        let rocket = rocket::build()
            .mount("/", routes![email_template])
            .manage(PkgClient::new(pkg_url));
        Client::tracked(rocket).await.expect("valid rocket")
    }

    #[rocket::async_test]
    async fn returns_template_for_valid_key() {
        let pkg_url = spawn_mock_pkg().await;
        let client = email_template_client(pkg_url).await;

        let res = client
            .get("/email-template")
            .header(Header::new("Authorization", "Bearer PG-key-with-template"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);

        let body: serde_json::Value = res.into_json().await.expect("json body");
        assert_eq!(body["tenant_id"].as_str(), Some("tenant-abc"));
        assert_eq!(
            body["email_template"].as_str(),
            Some("Beste {{naam}}, u heeft bestanden ontvangen.")
        );
    }

    #[rocket::async_test]
    async fn returns_401_for_missing_key() {
        // No Authorization header: the guard short-circuits to NoCredentials
        // without calling pg-pkg, so the PkgClient URL is never dialled.
        let client = email_template_client("http://127.0.0.1:1".to_owned()).await;
        let res = client.get("/email-template").dispatch().await;
        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn returns_401_for_invalid_key() {
        // A PG-prefixed key the mock rejects with 401 → guard yields no
        // tenant → endpoint returns 401.
        let pkg_url = spawn_mock_pkg().await;
        let client = email_template_client(pkg_url).await;

        let res = client
            .get("/email-template")
            .header(Header::new("Authorization", "Bearer PG-not-a-real-key"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn returns_404_for_valid_key_without_template() {
        let pkg_url = spawn_mock_pkg().await;
        let client = email_template_client(pkg_url).await;

        let res = client
            .get("/email-template")
            .header(Header::new("Authorization", "Bearer PG-key-no-template"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NotFound);
    }

    /// Serve `/v2/sign/parameters` from a plain thread: the first `failures`
    /// requests get a 503, subsequent ones the given JSON body. Returns the
    /// URL and a counter of requests seen.
    fn spawn_flaky_params_server(
        failures: usize,
        body: String,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let n = hits_srv.fetch_add(1, Ordering::SeqCst);
                let resp = if n < failures {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        (format!("http://127.0.0.1:{port}/v2/sign/parameters"), hits)
    }

    /// Regression test for encryption4all/postguard#235: cryptify panicked at
    /// startup when the PKG was briefly unreachable. The verifying-key fetch
    /// must retry transient failures and succeed once the PKG comes up.
    #[rocket::async_test]
    async fn verifying_key_fetch_survives_transient_pkg_outage() {
        use std::sync::atomic::Ordering;

        let mut rng = rand08::thread_rng();
        let setup = pg_core::test::TestSetup::new(&mut rng);
        let vk_json = serde_json::to_string(&Parameters {
            format_version: 0,
            public_key: VerifyingKey(setup.ibs_pk.0.clone()),
        })
        .expect("serialize test verifying key");

        // Fails twice, then serves a valid key.
        let (url, hits) = spawn_flaky_params_server(2, vk_json);

        let vk = try_fetch_verifying_key(
            &url,
            Duration::from_secs(10),
            Duration::from_millis(25),
            Duration::from_millis(100),
        )
        .await;

        assert!(vk.is_some(), "fetch must succeed after transient failures");
        assert!(
            hits.load(Ordering::SeqCst) >= 3,
            "expected at least 3 attempts (2 failures + 1 success)"
        );
    }

    /// When the PKG never becomes reachable, the fetch gives up after the
    /// budget (the caller then exits with a clear error) instead of retrying
    /// forever.
    #[rocket::async_test]
    async fn verifying_key_fetch_gives_up_after_budget() {
        // Always fails (no request ever gets past `failures`).
        let (url, _hits) = spawn_flaky_params_server(usize::MAX, String::new());

        let vk = try_fetch_verifying_key(
            &url,
            Duration::from_millis(200),
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .await;

        assert!(vk.is_none(), "fetch must give up once the budget is spent");
    }
}

/// Guards `api-description.yaml` against the routes the service actually
/// mounts. The spec is hand-maintained, so a new or renamed route silently
/// drifts away from it; this test fails the build instead.
#[cfg(test)]
mod api_description_tests {
    use super::*;

    const SPEC: &str = include_str!("../api-description.yaml");

    /// Operations declared in the spec, as `("GET", "/health")` pairs.
    ///
    /// Hand-rolled rather than parsed with a YAML crate to keep the
    /// dependency tree unchanged. It relies on the file's layout: path keys
    /// sit at two spaces of indentation under `paths:`, HTTP methods at four.
    /// `spec_layout_assumption_holds` fails loudly if that stops being true.
    fn spec_operations() -> Vec<(String, String)> {
        const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];
        let mut ops = Vec::new();
        let mut in_paths = false;
        let mut path: Option<String> = None;

        for line in SPEC.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // A top-level key ends the `paths:` block.
            if !line.starts_with(' ') {
                in_paths = line.starts_with("paths:");
                path = None;
                continue;
            }
            if !in_paths {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let key = line.trim_end().trim_start().trim_end_matches(':');
            if indent == 2 && key.starts_with('/') {
                path = Some(key.to_owned());
            } else if indent == 4 && METHODS.contains(&key) {
                if let Some(path) = path.as_ref() {
                    ops.push((key.to_uppercase(), path.clone()));
                }
            }
        }
        ops
    }

    /// Normalize a path so a Rocket route and a spec path compare equal:
    /// `/fileupload/<uuid>/status` and `/fileupload/{uuid}/status` both become
    /// `/fileupload/{}/status`. Placeholder *names* are dropped on purpose —
    /// they are labels with no effect on the wire contract, and the Rocket
    /// binding name (`<filename>`) is not always the name that documents the
    /// value best (`{uuid}`).
    fn normalize_path(path: &str) -> String {
        let mut out = String::with_capacity(path.len());
        let mut in_placeholder = false;
        for c in path.chars() {
            match c {
                '<' | '{' => {
                    in_placeholder = true;
                    out.push_str("{}");
                }
                '>' | '}' => in_placeholder = false,
                _ if in_placeholder => {}
                _ => out.push(c),
            }
        }
        out
    }

    #[test]
    fn spec_layout_assumption_holds() {
        assert!(
            !spec_operations().is_empty(),
            "no operations parsed out of api-description.yaml — the indentation \
             layout the parser assumes (paths at 2 spaces, methods at 4) changed"
        );
    }

    /// Mounted routes as `("GET", "/fileupload/<uuid>/status")` pairs.
    fn mounted_operations() -> Vec<(String, String)> {
        api_routes()
            .iter()
            .map(|route| (route.method.to_string(), route.uri.path().to_string()))
            .collect()
    }

    fn matches(ops: &[(String, String)], method: &str, path: &str) -> bool {
        ops.iter()
            .any(|(m, p)| m == method && normalize_path(p) == normalize_path(path))
    }

    #[test]
    fn every_mounted_route_is_in_the_spec() {
        let spec = spec_operations();
        for (method, path) in mounted_operations() {
            assert!(
                matches(&spec, &method, &path),
                "{} {} is mounted but missing from api-description.yaml",
                method,
                path
            );
        }
    }

    #[test]
    fn every_spec_operation_is_mounted() {
        let mounted = mounted_operations();
        for (method, path) in spec_operations() {
            assert!(
                matches(&mounted, &method, &path),
                "{} {} is in api-description.yaml but no route is mounted for it",
                method,
                path
            );
        }
    }
}

/// Guards the settings of the API breaking-change gate (issue #202).
///
/// The gate is `.github/workflows/api-diff.yml`, which runs `oasdiff breaking`
/// over `api-description.yaml` and is what stops a careless edit from breaking
/// a deployed client. Its whole behaviour is two step inputs, `fail-on` and
/// `include-checks`, and getting them wrong **fails open**: the job goes green
/// and nobody learns that the change it was supposed to stop went through.
///
/// So the inputs are pinned here. This module mutates the real spec one way
/// per rule, runs the real engine with the flags the action's entrypoint
/// builds, and asserts which mutations the gate stops.
///
/// The two halves are tied together rather than kept in step by hand:
/// [`the_workflow_uses_the_settings_this_module_pins`] reads the committed
/// workflow and asserts its `fail-on` and `include-checks` are [`FAIL_ON`] and
/// [`INCLUDE_CHECKS`], and that the job still runs at all — on `pull_request`,
/// with no path filter and no `if:`. Edit either side alone and that test says
/// so. It reads nothing but the repo tree, so unlike the mutation test it runs
/// on every runner.
///
/// The engine is not vendored, so these tests need `oasdiff` on `PATH` (or
/// `OASDIFF` pointing at it) and skip when it is absent, which is the case on
/// every runner. Install the version the action pins, so a local verdict is
/// CI's verdict:
///
/// ```text
/// go install github.com/oasdiff/oasdiff@v1.26.1
/// cargo test --all-targets api_gate
/// ```
#[cfg(test)]
mod api_gate_tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// `fail-on` in the workflow's oasdiff step. WARN, not ERR: at ERR the gate
    /// passes a removed or renamed optional response property, a removed
    /// request parameter or property, and the constraint-narrowing `*-set`
    /// family, all of which break a pinned client on unversioned routes.
    const FAIL_ON: &str = "WARN";

    /// `include-checks` in the workflow's oasdiff step. Both rate ERR but are
    /// opt-in, so they do not run unless named.
    const INCLUDE_CHECKS: &str =
        "response-non-success-status-removed,response-property-enum-value-removed";

    /// The gate itself, embedded so the two constants above cannot claim
    /// settings the committed job does not use.
    const WORKFLOW: &str = include_str!("../../.github/workflows/api-diff.yml");

    /// Path of the workflow, for failure messages.
    const WORKFLOW_PATH: &str = ".github/workflows/api-diff.yml";

    /// The value of the `key: value` step input in the workflow, or `None`
    /// when the key is absent.
    ///
    /// Hand-rolled rather than parsed with a YAML crate to keep the dependency
    /// tree unchanged, the same way `mod api_description_tests` above reads the
    /// spec. It relies on the input sitting alone on its line; comment lines
    /// are skipped, so the header comment's prose about `fail-on` does not
    /// count. More than one occurrence is a panic, because then "the
    /// workflow's setting" is not a single thing.
    fn workflow_input(key: &str) -> Option<String> {
        let prefix = format!("{key}:");
        let values: Vec<String> = WORKFLOW
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.strip_prefix(prefix.as_str()))
            .map(|value| value.trim().trim_matches(['"', '\'']).to_owned())
            .collect();
        assert!(
            values.len() <= 1,
            "{WORKFLOW_PATH} sets {key} {} times, so which one the gate runs \
             with is anyone's guess: {values:?}",
            values.len()
        );
        values.into_iter().next()
    }

    /// The non-comment lines of the workflow's `on:` block, from `on:` up to
    /// `jobs:`.
    ///
    /// Deliberately loose about the YAML shape, because `on:` is legal as a
    /// mapping, a list or a bare scalar and all three name the event inside
    /// this window. Matching the mapping form byte-for-byte would go red on a
    /// rewrite that changes nothing about when the gate runs, and a check that
    /// cries wolf is the one that gets deleted.
    fn trigger_block() -> Vec<&'static str> {
        WORKFLOW
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .skip_while(|line| !line.starts_with("on:"))
            .take_while(|line| !line.starts_with("jobs:"))
            .collect()
    }

    /// The constants above are only worth something if they describe the job
    /// that actually runs. Nothing else checks that: a wrong pair fails open,
    /// and so does a right pair the workflow never got.
    ///
    /// A gate that is present and correctly configured but never *triggered*
    /// fails open the same way and is the one thing the settings cannot show,
    /// so the trigger is asserted first: on `pull_request`, with no path filter
    /// and no `if:`. The workflow's own header comment names the foreseeable
    /// edit ("There is deliberately no `on: paths:` filter"), and a later
    /// `paths:` would skip the gate on every PR that does not touch the spec
    /// while everything below here stayed green.
    ///
    /// This needs no `oasdiff`, so it runs in CI where the mutation test skips.
    /// It is red on the branch that changes the settings until a maintainer
    /// applies the workflow patch (the App has no `workflows: write`), which is
    /// the intended order: the test goes green when the gate is real.
    #[test]
    fn the_workflow_uses_the_settings_this_module_pins() {
        assert!(
            WORKFLOW.contains("uses: oasdiff/oasdiff-action/breaking@"),
            "{WORKFLOW_PATH} no longer runs oasdiff-action/breaking, so this \
             module pins the settings of a job that is gone"
        );

        let triggers = trigger_block();
        assert!(
            triggers.iter().any(|line| line.contains("pull_request")),
            "{WORKFLOW_PATH} no longer triggers on `pull_request`, so the \
             settings pinned below belong to a gate that never sees one: \
             {triggers:?}"
        );
        assert!(
            !triggers
                .iter()
                .any(|line| line.starts_with("paths:") || line.starts_with("paths-ignore:")),
            "{WORKFLOW_PATH} has a path filter on its trigger, so the gate is \
             skipped on the PRs that do not touch the spec rather than passing \
             them, and as a required check it leaves those PRs pending forever: \
             {triggers:?}"
        );
        assert!(
            !WORKFLOW
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with('#'))
                .any(|line| line.starts_with("if:")),
            "{WORKFLOW_PATH} has an `if:` condition, so the gate can be skipped \
             on the very PRs it exists to judge while the settings below still \
             read correctly"
        );

        let expected = [
            ("fail-on", Some(FAIL_ON)),
            ("include-checks", Some(INCLUDE_CHECKS)),
        ];
        let wrong: Vec<String> = expected
            .iter()
            .filter_map(|(key, want)| {
                let got = workflow_input(key);
                (got.as_deref() != *want).then(|| {
                    format!(
                        "  {key}: the gate runs with {}, this module pins {}",
                        got.as_deref().unwrap_or("nothing"),
                        want.unwrap_or("nothing"),
                    )
                })
            })
            .collect();

        assert!(
            wrong.is_empty(),
            "{WORKFLOW_PATH} and this module disagree about what the gate \
             does:\n{}\n\
             Whichever side is behind, the other is a claim nothing backs: at \
             fail-on=ERR with no include-checks the gate passes ten of the \
             changes the spec's contract forbids, and the mutation test below \
             would certify settings it does not use.",
            wrong.join("\n"),
        );
    }

    /// Whether the gate stops a change, i.e. whether the job goes red.
    #[derive(Debug, PartialEq, Eq)]
    enum Gate {
        /// Additive as far as a deployed client is concerned.
        Passes,
        /// Breaking: cryptify's routes are unversioned, so this reaches every
        /// client pinned to the spec the moment it deploys.
        Stops,
    }

    impl Gate {
        fn verb(&self) -> &'static str {
            match self {
                Gate::Passes => "pass",
                Gate::Stops => "stop",
            }
        }

        fn past(&self) -> &'static str {
            match self {
                Gate::Passes => "passed",
                Gate::Stops => "stopped",
            }
        }
    }

    fn spec_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.yaml")
    }

    /// The `oasdiff` binary, or `None` when it is not installed.
    fn oasdiff() -> Option<PathBuf> {
        if let Some(explicit) = env::var_os("OASDIFF") {
            return Some(PathBuf::from(explicit));
        }
        let found = Command::new("oasdiff")
            .arg("--help")
            .output()
            .is_ok_and(|out| out.status.success());
        found.then(|| PathBuf::from("oasdiff"))
    }

    /// Replaces `old` with `new`, requiring `old` to occur exactly once so a
    /// spec edit that moves an anchor fails loudly instead of silently mutating
    /// nothing.
    fn once(text: &str, old: &str, new: &str) -> String {
        assert_eq!(
            text.matches(old).count(),
            1,
            "anchor is not unique in the spec, so this mutation no longer means \
             what it says: {old:?}"
        );
        text.replacen(old, new, 1)
    }

    /// The half-open byte range of the block starting at `start` and ending
    /// where the next `end` begins.
    fn block(text: &str, start: &str, end: &str) -> (usize, usize) {
        let from = text.find(start).unwrap_or_else(|| panic!("no {start:?}"));
        let to = text[from..]
            .find(end)
            .unwrap_or_else(|| panic!("no {end:?} after {start:?}"));
        (from, from + to)
    }

    /// Runs the gate exactly as the workflow's step does: the committed spec as
    /// the base, `revision` as the PR's version.
    ///
    /// The entrypoint of `oasdiff/oasdiff-action/breaking@v0.1.10` turns the
    /// step inputs into `--allow-external-refs=false --include-checks <checks>
    /// --composed=false --fail-on <level>`, so those are the flags used here.
    /// Exit 0 is a clean diff and exit 1 is "breaking changes found"; anything
    /// else is the engine refusing the input, which means the mutation produced
    /// a spec oasdiff cannot load and any verdict read off it is meaningless.
    fn gate(oasdiff: &Path, revision: &Path) -> Gate {
        let out = Command::new(oasdiff)
            .arg("breaking")
            .arg(spec_path())
            .arg(revision)
            .arg("--allow-external-refs=false")
            .args(["--include-checks", INCLUDE_CHECKS])
            .arg("--composed=false")
            .args(["--fail-on", FAIL_ON])
            .output()
            .expect("run oasdiff");

        match out.status.code() {
            Some(0) => Gate::Passes,
            Some(1) => Gate::Stops,
            other => panic!(
                "oasdiff exited {other:?} instead of 0 or 1, so it never reached \
                 a verdict:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ),
        }
    }

    // The spec blocks the mutations below anchor on. Each is unique in the
    // spec, and `once` fails the test if that ever stops being true.

    const RECOVERY_TOKEN_PARAMETER: &str = r##"      - in: "header"
        name: "X-Recovery-Token"
        description:
          "Bearer credential issued in the `recovery_token` field of
          the `upload_init` response. Compared in constant time on the
          server. Missing / empty → 401."
        schema:
          type: "string"
        required: true
"##;

    const RANGE_PARAMETER: &str = r##"      - in: "header"
        name: "Range"
        description:
          "Optional single byte range, `bytes=<start>-<end>`,
          `bytes=<start>-` or `bytes=-<suffix>`. Multiple ranges are not
          supported and are answered with 416."
        required: false
        schema:
          type: "string"
"##;

    const NOTIFY_RECIPIENTS_PROPERTY: &str = r##"                  notifyRecipients:
                    type: "boolean"
                    default: true
                    example: true
                    description: "Whether to email each recipient with a download link. Optional; defaults to true. Set to false to upload silently when the encrypted payload reaches recipients through another channel and a Cryptify-sent notification would be a duplicate."
"##;

    const SESSION_NOT_FOUND_REASONS: &str = r##"            - "expired_or_unknown"
            - "invalid_uuid"
            - "file_missing"
"##;

    const UPLOAD_STATUS_REQUIRED: &str = r##"      required:
        - uploaded
        - cryptify_token
      properties:
        uploaded:
"##;

    const USAGE_EMAIL_SCHEMA: &str = r##"        required: false
        schema:
          type: "string"
          format: "email"
"##;

    /// `/usage`'s `window_days`, taken together with the property that follows
    /// it. `/limits` declares a `window_days` of its own and its first two
    /// lines are byte-identical to these, so the shorter anchor names both.
    const USAGE_WINDOW_DAYS: &str = r##"                  window_days:
                    type: "integer"
                    description: "Length of the rolling window in days."
                  per_upload_limit_bytes:
"##;

    const EMAIL_TEMPLATE_503: &str =
        "        \"503\":\n          description: \"pg-pkg was unreachable while validating the API key.\"\n";

    // -----------------------------------------------------------------------
    // Additive: allowed, so the gate must let these through. A gate that stops
    // an additive change is worse than no gate, because the way around it is to
    // switch it off.
    // -----------------------------------------------------------------------

    fn add_endpoint(spec: &str) -> String {
        once(
            spec,
            "  /metrics:\n",
            r##"  /echo:
    get:
      tags:
        - "Health"
      summary: "Echo the request back"
      operationId: "echo"
      responses:
        "200":
          description: "ok"
  /metrics:
"##,
        )
    }

    fn add_optional_response_property(spec: &str) -> String {
        once(
            spec,
            "        prev_token:\n          type: \"string\"\n",
            r##"        stalled:
          type: "boolean"
          description: "Whether the upload has seen no chunk for a while."
        prev_token:
          type: "string"
"##,
        )
    }

    fn add_optional_request_property(spec: &str) -> String {
        once(
            spec,
            "                  notifyRecipients:\n",
            r##"                  clientHint:
                    type: "string"
                    description: "Free-form client identification."
                  notifyRecipients:
"##,
        )
    }

    fn add_required_response_property(spec: &str) -> String {
        once(
            spec,
            UPLOAD_STATUS_REQUIRED,
            r##"      required:
        - uploaded
        - cryptify_token
        - chunk_size
      properties:
        chunk_size:
          type: "integer"
          format: "int64"
        uploaded:
"##,
        )
    }

    fn add_optional_query_parameter(spec: &str) -> String {
        once(
            spec,
            "      operationId: \"health\"\n",
            r##"      operationId: "health"
      parameters:
      - in: "query"
        name: "verbose"
        required: false
        schema:
          type: "boolean"
"##,
        )
    }

    fn add_response_status(spec: &str) -> String {
        once(
            spec,
            EMAIL_TEMPLATE_503,
            &format!(
                "        \"429\":\n          description: \"Rate limited.\"\n{EMAIL_TEMPLATE_503}"
            ),
        )
    }

    fn edit_a_description(spec: &str) -> String {
        once(
            spec,
            "summary: \"Health check endpoint\"",
            "summary: \"Health check endpoint (liveness)\"",
        )
    }

    /// The only escape hatch cryptify has. Its routes are unversioned, so a
    /// change the current shape cannot take additively ships as a new versioned
    /// route with the old one left running. If the gate stopped this there
    /// would be no way to make a breaking change at all.
    fn add_versioned_route_beside_the_unversioned_one(spec: &str) -> String {
        let (from, to) = block(spec, "  /usage:\n", "  /email-template:\n");
        let versioned = once(&spec[from..to], "  /usage:\n", "  /v2/usage:\n");
        let versioned = once(
            &versioned,
            "operationId: \"getUsage\"\n",
            "operationId: \"getUsageV2\"\n",
        );
        once(
            spec,
            "  /email-template:\n",
            &format!("{versioned}  /email-template:\n"),
        )
    }

    /// A wider *request* enum is additive: the server accepts a language it did
    /// not before, and no deployed client sends one it does not know about.
    fn add_a_request_enum_value(spec: &str) -> String {
        once(
            spec,
            "enum: [\"EN\", \"NL\"]",
            "enum: [\"EN\", \"NL\", \"DE\"]",
        )
    }

    fn add_optional_response_header(spec: &str) -> String {
        once(
            spec,
            r##"          description: "Successful operation"
        "400":
          description:
            "The `cryptifytoken` header does not match the token the server
"##,
            r##"          description: "Successful operation"
          headers:
            X-Upload-Id:
              schema:
                type: "string"
        "400":
          description:
            "The `cryptifytoken` header does not match the token the server
"##,
        )
    }

    // -----------------------------------------------------------------------
    // Breaking: each one breaks a client written against today's spec, and on
    // unversioned routes there is nowhere for such a client to stay.
    // -----------------------------------------------------------------------

    fn remove_route(spec: &str) -> String {
        let (from, to) = block(spec, "  /email-template:\n", "  /filedownload/{uuid}:\n");
        format!("{}{}", &spec[..from], &spec[to..])
    }

    fn request_property_becomes_required(spec: &str) -> String {
        once(
            spec,
            "                  - confirm\n",
            "                  - confirm\n                  - notifyRecipients\n",
        )
    }

    /// A client that handles 401 by prompting for an API key sees an unhandled
    /// 403.
    fn change_a_status_code(spec: &str) -> String {
        once(
            spec,
            r##"        "401":
          description:
            "No valid `Authorization: Bearer PG-…` API key was presented. Usage
"##,
            r##"        "403":
          description:
            "No valid `Authorization: Bearer PG-…` API key was presented. Usage
"##,
        )
    }

    fn remove_a_non_success_status(spec: &str) -> String {
        once(spec, EMAIL_TEMPLATE_503, "")
    }

    fn remove_a_response_enum_value(spec: &str) -> String {
        once(
            spec,
            SESSION_NOT_FOUND_REASONS,
            "            - \"expired_or_unknown\"\n            - \"invalid_uuid\"\n",
        )
    }

    /// The one rule the gate adds on top of "no removing or narrowing": a
    /// widened *response* enum is a change a client cannot see coming, and it
    /// is caught only at WARN, so a revert to `fail-on: ERR` drops it silently
    /// unless it is pinned here. See CLAUDE.md for the reasoning.
    fn add_a_response_enum_value(spec: &str) -> String {
        once(
            spec,
            SESSION_NOT_FOUND_REASONS,
            &format!("{SESSION_NOT_FOUND_REASONS}            - \"quota_exceeded\"\n"),
        )
    }

    /// `prev_offset` is optional only because it is absent until the first
    /// chunk lands; a resuming client reads it on every recovery.
    fn remove_optional_response_property(spec: &str) -> String {
        once(
            spec,
            r##"        prev_offset:
          type: "integer"
          format: "int64"
          description:
            "Byte offset where the most recently committed chunk started
            (i.e. `uploaded - chunk_len`). Omitted until at least one
            chunk has been committed."
"##,
            "",
        )
    }

    fn rename_optional_response_property(spec: &str) -> String {
        once(
            spec,
            "        prev_token:\n          type: \"string\"\n",
            "        previous_token:\n          type: \"string\"\n",
        )
    }

    fn remove_required_response_property(spec: &str) -> String {
        once(
            spec,
            r##"      required:
        - uploaded
        - cryptify_token
      properties:
        uploaded:
          type: "integer"
          format: "int64"
          description:
            "Total bytes the server has committed for this upload so far.
            The client should resume from this offset."
"##,
            "      required:\n        - cryptify_token\n      properties:\n",
        )
    }

    fn narrow_a_response_property_type(spec: &str) -> String {
        once(
            spec,
            USAGE_WINDOW_DAYS,
            &USAGE_WINDOW_DAYS.replace("type: \"integer\"", "type: \"string\""),
        )
    }

    /// The constraint-narrowing `*-set` family: a value the server used to
    /// accept now fails validation.
    fn narrow_a_request_parameter(spec: &str) -> String {
        once(
            spec,
            USAGE_EMAIL_SCHEMA,
            &format!("{USAGE_EMAIL_SCHEMA}          maxLength: 64\n"),
        )
    }

    fn remove_a_required_request_parameter(spec: &str) -> String {
        once(spec, RECOVERY_TOKEN_PARAMETER, "")
    }

    fn remove_an_optional_request_parameter(spec: &str) -> String {
        once(spec, RANGE_PARAMETER, "")
    }

    fn remove_a_request_property(spec: &str) -> String {
        once(spec, NOTIFY_RECIPIENTS_PROPERTY, "")
    }

    fn remove_a_response_media_type(spec: &str) -> String {
        once(
            spec,
            r##"        "200":
          description: "Service is healthy"
          content:
            text/plain:
              schema:
                type: "string"
                example: "OK"
"##,
            "        \"200\":\n          description: \"Service is healthy\"\n",
        )
    }

    fn remove_a_required_response_header(spec: &str) -> String {
        once(
            spec,
            r##"          headers:
            cryptifytoken:
              required: true
              schema:
                description: "Identifies the new version of the upload file parts. Needs to be passed into the next file part upload request."
                type: "string"
"##,
            "",
        )
    }

    type Mutation = (&'static str, fn(&str) -> String, Gate);

    fn mutations() -> Vec<Mutation> {
        vec![
            ("a new endpoint", add_endpoint, Gate::Passes),
            (
                "a new optional response property",
                add_optional_response_property,
                Gate::Passes,
            ),
            (
                "a new optional request property",
                add_optional_request_property,
                Gate::Passes,
            ),
            (
                "a new required response property",
                add_required_response_property,
                Gate::Passes,
            ),
            (
                "a new optional query parameter",
                add_optional_query_parameter,
                Gate::Passes,
            ),
            ("a new response status", add_response_status, Gate::Passes),
            ("an edited description", edit_a_description, Gate::Passes),
            (
                "a versioned route beside the unversioned one",
                add_versioned_route_beside_the_unversioned_one,
                Gate::Passes,
            ),
            (
                "a new request enum value",
                add_a_request_enum_value,
                Gate::Passes,
            ),
            (
                "a new optional response header",
                add_optional_response_header,
                Gate::Passes,
            ),
            ("a removed route", remove_route, Gate::Stops),
            (
                "a request property becoming required",
                request_property_becomes_required,
                Gate::Stops,
            ),
            ("a changed status code", change_a_status_code, Gate::Stops),
            (
                "a removed non-success status",
                remove_a_non_success_status,
                Gate::Stops,
            ),
            (
                "a removed response enum value",
                remove_a_response_enum_value,
                Gate::Stops,
            ),
            (
                "a new response enum value",
                add_a_response_enum_value,
                Gate::Stops,
            ),
            (
                "a removed optional response property",
                remove_optional_response_property,
                Gate::Stops,
            ),
            (
                "a renamed optional response property",
                rename_optional_response_property,
                Gate::Stops,
            ),
            (
                "a removed required response property",
                remove_required_response_property,
                Gate::Stops,
            ),
            (
                "a narrowed response property type",
                narrow_a_response_property_type,
                Gate::Stops,
            ),
            (
                "a narrowed request parameter constraint",
                narrow_a_request_parameter,
                Gate::Stops,
            ),
            (
                "a removed required request parameter",
                remove_a_required_request_parameter,
                Gate::Stops,
            ),
            (
                "a removed optional request parameter",
                remove_an_optional_request_parameter,
                Gate::Stops,
            ),
            (
                "a removed request property",
                remove_a_request_property,
                Gate::Stops,
            ),
            (
                "a removed response media type",
                remove_a_response_media_type,
                Gate::Stops,
            ),
            (
                "a removed required response header",
                remove_a_required_response_header,
                Gate::Stops,
            ),
        ]
    }

    /// Every mutation must still edit the spec, whether or not oasdiff is
    /// installed, so a spec edit that strands an anchor is caught in CI too.
    #[test]
    fn every_api_gate_mutation_still_applies() {
        let spec = fs::read_to_string(spec_path()).expect("read the spec");
        for (name, mutate, _) in mutations() {
            assert_ne!(
                mutate(&spec),
                spec,
                "the mutation for {name} changed nothing, so whatever it \
                 asserts is vacuous"
            );
        }
    }

    #[test]
    fn the_api_gate_stops_breaking_changes_and_passes_additive_ones() {
        let Some(oasdiff) = oasdiff() else {
            eprintln!(
                "skipping: oasdiff is not installed, which is the case on every \
                 runner. To run this test, `go install \
                 github.com/oasdiff/oasdiff@v1.26.1` (the version the action \
                 pins), or set OASDIFF."
            );
            return;
        };

        let spec = fs::read_to_string(spec_path()).expect("read the spec");
        let dir = env::temp_dir().join(format!("cryptify-api-gate-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create the scratch directory");

        // The unmutated spec first: without this, a gate that stopped
        // everything would satisfy every Stops case below and only look half
        // broken.
        let unchanged = dir.join("unchanged.yaml");
        fs::write(&unchanged, &spec).expect("write the spec");
        let baseline = gate(&oasdiff, &unchanged);

        let mut wrong = Vec::new();
        if baseline != Gate::Passes {
            wrong.push("  no change at all: the gate should pass it, it stopped it".to_owned());
        }
        for (name, mutate, expected) in mutations() {
            let slug: String = name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();
            let revision = dir.join(format!("{slug}.yaml"));
            fs::write(&revision, mutate(&spec)).expect("write the mutated spec");
            let actual = gate(&oasdiff, &revision);
            if actual != expected {
                wrong.push(format!(
                    "  {name}: the gate should {} it, it {} it",
                    expected.verb(),
                    actual.past()
                ));
            }
        }

        fs::remove_dir_all(&dir).ok();
        assert!(
            wrong.is_empty(),
            "the gate's verdict on {} of {} changes is not what fail-on={FAIL_ON} \
             and include-checks={INCLUDE_CHECKS} are supposed to deliver:\n{}",
            wrong.len(),
            mutations().len() + 1,
            wrong.join("\n"),
        );
    }
}
