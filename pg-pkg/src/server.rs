use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_http::header::HttpDate;
use actix_web::http::header::EntityTag;
use actix_web::{
    guard::Guard,
    http::header,
    middleware::Logger,
    web,
    web::{resource, scope, Data},
    App, HttpServer,
};

use crate::middleware::auth::{Auth, AuthType};
use crate::middleware::metrics::collect_metrics;
use crate::middleware::ratelimit::ClientIpKeyExtractor;
use crate::opts::*;
use crate::util::*;
use crate::{handlers, PKGError};

use pg_core::api::Parameters;
use pg_core::artifacts::*;
use pg_core::kem::cgw_kv::CGWKV;

use prometheus::{register_int_counter_vec, IntCounterVec};
use sqlx::postgres::PgPoolOptions;
use std::sync::LazyLock;

pub(crate) static POSTGUARD_CLIENTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "postguard_clients",
        "Contains information about PostGuard clients connecting with the PKG.",
        &[
            "path",
            "host",
            "host_version",
            "client",
            "client_version",
            "status"
        ]
    )
    .expect("could not initialize metrics")
});

/// Guard that checks if the Authorization header contains a postguard-business
/// API key. Business-issued keys are `PG-<base64url>` (see
/// `postguard-business/src/lib/server/services/api-keys.ts`). JWTs and IRMA
/// tokens fall through to other routes.
struct ApiKeyGuard;

impl Guard for ApiKeyGuard {
    fn check(&self, ctx: &actix_web::guard::GuardContext) -> bool {
        ctx.head()
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|auth| {
                auth.strip_prefix("Bearer ")
                    .or_else(|| auth.strip_prefix("bearer "))
                    .map(|token| token.starts_with("PG-"))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}

/// JSON body handling for the `/v2` scope. Body-deserialization failures
/// (malformed JSON, unknown or missing fields — the request types are
/// `#[serde(deny_unknown_fields)]`) become a 400 in the documented
/// `{error, message}` envelope, carrying serde's client-actionable message
/// (e.g. ``unknown field `vaule`, expected one of `t`, `v`, `optional```).
fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(64 * 1024)
        .error_handler(|err, _req| {
            let body = serde_json::json!({
                "error": true,
                "message": err.to_string(),
            });
            actix_web::error::InternalError::from_response(
                err,
                actix_web::HttpResponse::BadRequest().json(body),
            )
            .into()
        })
}

/// Precomputed parameter data.
#[derive(Debug, Clone)]
pub struct ParametersData {
    /// Pre-serialized public parameters (JSON).
    pub pp: String,

    /// Last modified.
    pub last_modified: HttpDate,

    /// Etag.
    pub etag: EntityTag,
}

#[actix_rt::main]
pub async fn exec(server_opts: ServerOpts) -> Result<(), PKGError> {
    let ServerOpts {
        host,
        port,
        database_url,
        irma,
        irma_token,
        ibe_secret_path,
        ibe_public_path,
        ibs_secret_path,
        ibs_public_path,
        allowed_origins,
        ratelimit_disabled,
        ratelimit_per_second,
        ratelimit_burst,
        ratelimit_sensitive_per_second,
        ratelimit_sensitive_burst,
        ratelimit_trust_forwarded_for,
    } = server_opts;

    let allow_any_origin = allowed_origins.iter().any(|o| o == "*");
    if allow_any_origin {
        log::warn!(
            "PKG CORS: allowing any origin (\"*\"). Set --allowed-origins (or PKG_ALLOWED_ORIGINS) to a comma-separated allowlist for production."
        );
    } else {
        log::info!(
            "PKG CORS: restricting to {} allowed origin(s): {:?}",
            allowed_origins.len(),
            allowed_origins
        );
    }

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Connect to the postguard-business database for API-key validation.
    // pg-pkg does NOT own this schema and does not run migrations — the
    // `organizations` and `business_api_keys` tables are owned by the
    // postguard-business service.
    let db_pool = match &database_url {
        Some(url) => {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(url)
                .await
                .map_err(|e| {
                    log::error!("Failed to connect to business database: {}", e);
                    PKGError::Setup(format!("Failed to connect to business database: {}", e))
                })?;
            log::info!("Connected to postguard-business database for API-key validation");
            Some(Data::new(pool))
        }
        None => {
            log::info!(
                "No business database URL provided; API-key authentication will be disabled"
            );
            None
        }
    };

    let (ibe_pk, ibe_sk) = cgwkv_read_key_pair(&ibe_public_path, &ibe_secret_path)?;
    let (ibs_pk, ibs_sk) = gg_read_key_pair(&ibs_public_path, &ibs_secret_path)?;

    let ibe_pd = ParametersData::new(
        &Parameters::<PublicKey<CGWKV>> {
            format_version: 0x00,
            public_key: PublicKey(ibe_pk),
        },
        Some(&ibe_public_path),
    )?;

    let ibs_pd = ParametersData::new(
        &Parameters::<VerifyingKey> {
            format_version: 0x00,
            public_key: VerifyingKey(ibs_pk),
        },
        Some(&ibs_public_path),
    )?;

    // Per-IP rate limiting (actix-governor, keyed on the peer IP address).
    // Two tiers: a permissive limit on the whole `/v2` scope to cap overall
    // load, and a stricter limit on the key-issuing endpoints. When
    // `--ratelimit-disabled` is set the middleware is built in permissive mode
    // so it passes every request through unchanged (useful behind a trusted
    // proxy that does its own rate limiting).
    if ratelimit_disabled {
        log::warn!(
            "PKG rate limiting: DISABLED. Only do this behind a trusted reverse proxy that rate-limits itself."
        );
    } else {
        log::info!(
            "PKG rate limiting: /v2 = {}/s (burst {}), key endpoints = {}/s (burst {}), keyed on {}",
            ratelimit_per_second,
            ratelimit_burst,
            ratelimit_sensitive_per_second,
            ratelimit_sensitive_burst,
            if ratelimit_trust_forwarded_for {
                "client IP (X-Forwarded-For)"
            } else {
                "peer IP"
            },
        );
    }

    // Both configs share their underlying rate-limiter state across workers
    // because `GovernorConfig::clone` only clones the internal `Arc`. The key
    // extractor decides whether a "client" is the peer address or the real
    // client IP from `X-Forwarded-For` (see `ClientIpKeyExtractor`); behind our
    // ingress the peer is always the proxy, so `--ratelimit-trust-forwarded-for`
    // must be set for per-client limiting to be meaningful.
    let make_config = |per_second: u64, burst: u32| {
        let mut default_builder = GovernorConfigBuilder::default();
        let mut builder = default_builder.key_extractor(ClientIpKeyExtractor {
            trust_forwarded_for: ratelimit_trust_forwarded_for,
        });
        builder
            .requests_per_second(per_second.max(1))
            .burst_size(burst.max(1));
        builder
            .permissive(ratelimit_disabled)
            .finish()
            .expect("invalid rate-limit configuration")
    };
    let general_ratelimit = make_config(ratelimit_per_second, ratelimit_burst);
    let sensitive_ratelimit =
        make_config(ratelimit_sensitive_per_second, ratelimit_sensitive_burst);

    HttpServer::new(move || {
        let mut app = App::new()
            .wrap(
                Logger::new(
                    "request=%{PATH}xi, status=%s, client=%{CLIENT_ID}xi, response_time=%D ms",
                )
                .custom_request_replace("CLIENT_ID", client_version)
                .custom_request_replace("PATH", |req| {
                    req.match_pattern().unwrap_or("-".to_string())
                }),
            )
            .wrap({
                let mut cors = Cors::default()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_header(header::CONTENT_TYPE)
                    .allowed_header(header::AUTHORIZATION)
                    .allowed_header(header::ETAG)
                    .allowed_header(PG_CLIENT_HEADER)
                    .max_age(86400);
                if allow_any_origin {
                    cors = cors.allow_any_origin();
                } else {
                    for origin in &allowed_origins {
                        cors = cors.allowed_origin(origin);
                    }
                }
                cors
            });

        // Add database pool to app data if available
        if let Some(ref pool) = db_pool {
            app = app.app_data(Data::clone(pool));
        }

        let mut v2 = scope("/v2")
            .wrap_fn(collect_metrics)
            // Registered last => outermost: reject over-limit requests before
            // they hit metrics collection or any handler. actix applies `wrap`
            // layers in reverse registration order, so the Governor must be
            // wrapped after `collect_metrics` to sit in front of it.
            .wrap(Governor::new(&general_ratelimit))
            // Body-deserialization failures (malformed JSON, unknown/missing
            // fields — request types are #[serde(deny_unknown_fields)]) must
            // use the documented {error, message} envelope, not actix's
            // default plain-text body. The serde message is client-actionable
            // ("unknown field `vaule`, expected one of `t`, `v`, `optional`").
            .app_data(Data::new(json_config()))
            .service(
                resource("/parameters")
                    .app_data(Data::new(ibe_pd.clone()))
                    .route(web::get().to(handlers::parameters)),
            )
            .service(
                resource("/sign/parameters")
                    .app_data(Data::new(ibs_pd.clone()))
                    .route(web::get().to(handlers::parameters)),
            );

        // `/v2/api-key/validate` — sibling services (cryptify) call this to
        // confirm a `PG-…` key is valid and read the tenant id without going
        // through signing-key issuance. Only registered when a database pool
        // is configured, since validation requires the business schema.
        if let Some(ref pool) = db_pool {
            v2 = v2.service(
                resource("/api-key/validate")
                    .guard(ApiKeyGuard)
                    // Registered last => outermost: rate-limit before auth work.
                    .wrap(
                        Auth::new(irma.clone(), AuthType::Key).with_db_pool(pool.as_ref().clone()),
                    )
                    .wrap(Governor::new(&sensitive_ratelimit))
                    .route(web::get().to(handlers::api_key_validate)),
            );
        }

        v2 = v2.service({
            let mut irma_scope = scope("/{_:(irma|request)}")
                .service(
                    resource("/start")
                        .app_data(Data::new(IrmaUrl(irma.clone())))
                        .app_data(Data::new(IrmaToken(irma_token.clone())))
                        .wrap(Governor::new(&sensitive_ratelimit))
                        .route(web::post().to(handlers::start)),
                )
                .service(
                    resource("/jwt/{token}")
                        .app_data(Data::new(IrmaUrl(irma.clone())))
                        .route(web::get().to(handlers::jwt)),
                )
                .service(
                    resource("/statusevents/{token}")
                        .app_data(Data::new(IrmaUrl(irma.clone())))
                        .route(web::get().to(handlers::statusevents)),
                )
                .service(
                    resource("/key/{timestamp}")
                        .app_data(Data::new(ibe_sk))
                        .wrap(Auth::new(irma.clone(), AuthType::Jwt))
                        .wrap(Governor::new(&sensitive_ratelimit))
                        .route(web::get().to(handlers::key::<CGWKV>)),
                )
                .service(
                    resource("/key")
                        .app_data(Data::new(ibe_sk))
                        .wrap(Auth::new(irma.clone(), AuthType::Jwt))
                        .wrap(Governor::new(&sensitive_ratelimit))
                        .route(web::get().to(handlers::key::<CGWKV>)),
                );

            // API Key authentication (when header starts with "PG-")
            // Only register this service when a database pool is configured
            if let Some(ref pool) = db_pool {
                irma_scope = irma_scope.service(
                    resource("/sign/key")
                        .guard(ApiKeyGuard)
                        .app_data(Data::new(ibs_sk.clone()))
                        .wrap(
                            Auth::new(irma.clone(), AuthType::Key)
                                .with_db_pool(pool.as_ref().clone()),
                        )
                        .wrap(Governor::new(&sensitive_ratelimit))
                        .route(web::post().to(handlers::signing_key)),
                );
            }

            // JWT authentication (fallback for all other tokens)
            irma_scope.service(
                resource("/sign/key")
                    .app_data(Data::new(ibs_sk.clone()))
                    .wrap(Auth::new(irma.clone(), AuthType::Jwt))
                    .wrap(Governor::new(&sensitive_ratelimit))
                    .route(web::post().to(handlers::signing_key)),
            )
        });

        app.service(resource("/metrics").route(web::get().to(handlers::metrics)))
            .service(resource("/health").route(web::get().to(handlers::health)))
            .service(v2)
    })
    .bind(format!("{host}:{port}"))?
    .shutdown_timeout(1)
    .run()
    .await?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use actix_http::Request;
    use actix_web::dev::{Service, ServiceResponse};
    use actix_web::{test, web, App, Error};

    use crate::middleware::irma_noauth::NoAuth;
    use irma::{ProofStatus, SessionStatus};
    use pg_core::api::{KeyResponse, Parameters, SigningKeyRequest, SigningKeyResponse};
    use pg_core::ibs::gg;
    use pg_core::identity::{Attribute, Policy};
    use pg_core::kem::IBKEM;

    use crate::middleware::auth::tests::MockApiKeyStore;
    use crate::middleware::auth::ApiKeyData;
    use rand::thread_rng;
    use std::time::SystemTime;

    pub(crate) fn now() -> u64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub(crate) async fn default_setup() -> (
        impl Service<Request, Response = ServiceResponse, Error = Error>,
        <CGWKV as IBKEM>::Pk,
        <CGWKV as IBKEM>::Sk,
        gg::PublicKey,
        gg::SecretKey,
    ) {
        let mut rng = thread_rng();

        let (ibe_pk, ibe_sk) = CGWKV::setup(&mut rng);
        let (ibs_pk, ibs_sk) = gg::setup(&mut rng);

        let pd = ParametersData::new(
            &Parameters::<PublicKey<CGWKV>> {
                format_version: 0x00,
                public_key: PublicKey(ibe_pk),
            },
            None,
        )
        .unwrap();

        let pds = ParametersData::new(
            &Parameters::<VerifyingKey> {
                format_version: 0x00,
                public_key: VerifyingKey(ibs_pk.clone()),
            },
            None,
        )
        .unwrap();

        // Create a simple setup with a pk endpoint and a key service without authentication.
        let app = test::init_service(
            App::new()
                .service(resource("/metrics").route(web::get().to(handlers::metrics)))
                .service(
                    scope("/v2")
                        .wrap_fn(collect_metrics)
                        .service(
                            resource("/parameters")
                                .app_data(Data::new(pd))
                                .route(web::get().to(handlers::parameters)),
                        )
                        .service(
                            resource("/sign/parameters")
                                .app_data(Data::new(pds))
                                .route(web::get().to(handlers::parameters)),
                        )
                        .service(
                            resource("/key/{timestamp}")
                                .app_data(Data::new(ibe_sk))
                                .wrap(NoAuth::Decryption)
                                .route(web::get().to(handlers::key::<CGWKV>)),
                        )
                        .service(
                            resource("/key")
                                .app_data(Data::new(ibe_sk))
                                .wrap(NoAuth::Decryption)
                                .route(web::get().to(handlers::key::<CGWKV>)),
                        )
                        .service(
                            resource("/sign/key")
                                .app_data(Data::new(ibs_sk.clone()))
                                .wrap(NoAuth::Signing)
                                .route(web::post().to(handlers::signing_key)),
                        ),
                ),
        )
        .await;

        (app, ibe_pk, ibe_sk, ibs_pk, ibs_sk)
    }

    #[actix_web::test]
    async fn test_get_parameters() {
        let (app, pk, _, _, _) = default_setup().await;

        let resp = test::TestRequest::get()
            .uri("/v2/parameters")
            .send_request(&app)
            .await;

        assert!(resp.headers().contains_key("last-modified"));
        assert!(resp.headers().contains_key("cache-control"));
        assert!(resp.headers().contains_key("etag"));

        let params: Parameters<PublicKey<CGWKV>> = test::read_body_json(resp).await;
        assert_eq!(&params.public_key.0, &pk);
        assert_eq!(params.format_version, 0x00);
    }

    #[actix_web::test]
    async fn test_get_parameters_signing() {
        let (app, _, _, pk, _) = default_setup().await;

        let resp = test::TestRequest::get()
            .uri("/v2/sign/parameters")
            .send_request(&app)
            .await;

        assert!(resp.headers().contains_key("last-modified"));
        assert!(resp.headers().contains_key("cache-control"));
        assert!(resp.headers().contains_key("etag"));

        let params: Parameters<VerifyingKey> = test::read_body_json(resp).await;
        assert_eq!(&params.public_key.0, &pk);
        assert_eq!(params.format_version, 0x00);
    }

    #[actix_web::test]
    async fn test_get_usk() {
        let (app, _, _, _, _) = default_setup().await;

        let ts = now();

        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let req = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol.clone())
            .to_request();

        let key_response: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req).await;

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));
    }

    #[actix_web::test]
    async fn test_get_usk_no_timestamp() {
        let (app, _, _, _, _) = default_setup().await;

        let pol = Policy {
            timestamp: now(),
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let req = test::TestRequest::get()
            .uri("/v2/key")
            .set_json(pol)
            .to_request();

        let key_response: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req).await;

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));
        assert!(key_response.key.is_some());
    }

    #[actix_web::test]
    async fn test_get_usk_signing() {
        let (app, _, _, _, _) = default_setup().await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![Attribute::new("testattribute", Some("testvalue"))],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .set_json(skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        let key_response: SigningKeyResponse = test::try_read_body_json(resp).await.unwrap();

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));
        assert!(key_response.pub_sign_key.is_some());
        assert!(key_response.priv_sign_key.is_none());
    }

    #[actix_web::test]
    async fn test_get_usk_signing_with_private() {
        let (app, _, _, _, _) = default_setup().await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![Attribute::new("testattribute", None)],
            priv_sign_id: Some(vec![Attribute::new("private test attribute", None)]),
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        let key_response: SigningKeyResponse = test::try_read_body_json(resp).await.unwrap();

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));
        assert!(key_response
            .pub_sign_key
            .is_some_and(|k| k.policy.con == skr.pub_sign_id));
        assert!(key_response
            .priv_sign_key
            .is_some_and(|k| k.policy.con == skr.priv_sign_id.unwrap()));
    }

    #[actix_web::test]
    async fn test_round_signing() {
        let mut rng = thread_rng();
        let (app, _, _, pks, _) = default_setup().await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![Attribute::new("testattribute", None)],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .set_json(skr)
            .to_request();

        let key_response: SigningKeyResponse = test::call_and_read_body_json(&app, req).await;

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));

        let pub_sign_key = key_response.pub_sign_key.unwrap();
        let id = pub_sign_key.policy.derive_ibs().unwrap();

        let message = b"some identical message";
        let sig = gg::Signer::new()
            .chain(message)
            .sign(&pub_sign_key.key.0, &mut rng);

        assert!(gg::Verifier::new().chain(message).verify(&pks, &sig, &id));
        assert!(!gg::Verifier::new()
            .chain("some other message")
            .verify(&pks, &sig, &id));
    }

    #[actix_web::test]
    async fn test_round_kem() {
        let mut rng = thread_rng();
        let (app, _, sk, _, _) = default_setup().await;

        let ts = now();

        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let id = pol.derive_kem::<CGWKV>().unwrap();

        let req_pk = test::TestRequest::get().uri("/v2/parameters").to_request();
        let ppk: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req_pk).await;

        // Encapsulate a shared secret using the MPK from the PKG API.
        let (ct, ss1) = CGWKV::encaps(&ppk.public_key.0, &id, &mut rng);

        let req_usk = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol.clone())
            .to_request();

        let key_response: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req_usk).await;

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));

        // Make sure a USK retrieved from the PKG API can decapsulate.
        let ss2 = CGWKV::decaps(None, &key_response.key.unwrap().0, &ct).unwrap();
        assert_eq!(ss1, ss2);

        // Make sure a key derived from the original MSK can decapsulate as well.
        let usk2 = CGWKV::extract_usk(None, &sk, &id, &mut rng);
        let ss3 = CGWKV::decaps(None, &usk2, &ct).unwrap();
        assert_eq!(ss1, ss3);
    }

    #[actix_web::test]
    async fn test_round_kem_wrong_policy() {
        let mut rng = thread_rng();
        let (app, _, _, _, _) = default_setup().await;

        let ts = now();

        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let id = pol.derive_kem::<CGWKV>().unwrap();

        let req_pk = test::TestRequest::get().uri("/v2/parameters").to_request();
        let ppk: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req_pk).await;

        // Encapsulate a shared secret for pol using the MPK from the PKG API.
        let (ct, ss1) = CGWKV::encaps(&ppk.public_key.0, &id, &mut rng);

        let req_usk = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol.clone())
            .to_request();

        let key_response: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req_usk).await;

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));

        // Make sure a USK retrieved from the PKG API for pol can decapsulate.
        let ss2 = CGWKV::decaps(None, &key_response.key.unwrap().0, &ct).unwrap();
        assert_eq!(ss1, ss2);

        // Test that if a USK is retrieved for a different policy, decapsulation will fail.
        let pol_wrong = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("anothervalue"))],
        };

        let req_usk_wrong = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol_wrong)
            .to_request();

        let key_response_wrong: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req_usk_wrong).await;

        // Make sure a USK retrieved for a different policy cannot decapsulate.
        let ss4 = CGWKV::decaps(None, &key_response_wrong.key.unwrap().0, &ct).unwrap();
        assert_ne!(ss1, ss4);
    }

    fn default_api_key_data(email: &str) -> ApiKeyData {
        ApiKeyData {
            org_id: "00000000-0000-0000-0000-000000000001".to_string(),
            email: email.to_string(),
            organisation_name: None,
            phone_number: None,
            kvk_number: None,
            organisation_name_public: false,
            phone_number_public: false,
            kvk_number_public: false,
        }
    }

    async fn setup_api_key_test_with_mock_store(
        key: String,
        data: ApiKeyData,
    ) -> (
        impl Service<Request, Response = ServiceResponse, Error = Error>,
        gg::PublicKey,
    ) {
        let (_, _, _, ibs_pk, ibs_sk) = default_setup().await;
        let irma = "https://irma.example.org".to_string();

        let mock_store = if key.is_empty() {
            MockApiKeyStore::new()
        } else {
            MockApiKeyStore::new().with_key(key, data)
        };

        let app = test::init_service(
            App::new().service(
                scope("/v2").service(
                    resource("/sign/key")
                        .app_data(Data::new(ibs_sk.clone()))
                        .wrap(Auth::new(irma.clone(), AuthType::Key).with_api_key_store(mock_store))
                        .route(web::post().to(handlers::signing_key)),
                ),
            ),
        )
        .await;

        (app, ibs_pk)
    }

    #[actix_web::test]
    async fn test_api_key_signing_email_only() {
        let (app, _) = setup_api_key_test_with_mock_store(
            "PG-valid-key".to_string(),
            default_api_key_data("test@example.com"),
        )
        .await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-valid-key"))
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        let key_response: SigningKeyResponse = test::try_read_body_json(resp).await.unwrap();

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));

        // Email is always public
        let pub_key = key_response.pub_sign_key.unwrap();
        assert_eq!(pub_key.policy.con.len(), 1);
        assert_eq!(pub_key.policy.con[0].atype, "pbdf.sidn-pbdf.email.email");
        assert!(key_response.priv_sign_key.is_none());
    }

    #[actix_web::test]
    async fn test_api_key_signing_invalid_key() {
        let (app, _) = setup_api_key_test_with_mock_store(
            "PG-valid-key".to_string(),
            default_api_key_data("test@example.com"),
        )
        .await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-invalid-key"))
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await;
        assert!(resp.is_err(), "Expected error for invalid API key");
    }

    #[actix_web::test]
    async fn test_api_key_signing_empty_store() {
        let (app, _) =
            setup_api_key_test_with_mock_store("".to_string(), default_api_key_data("")).await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-invalid-key"))
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await;
        assert!(resp.is_err(), "Expected error for invalid API key");
    }

    #[actix_web::test]
    async fn test_api_key_signing_round_trip() {
        let mut rng = thread_rng();
        let (app, ibs_pk) = setup_api_key_test_with_mock_store(
            "PG-valid-key".to_string(),
            default_api_key_data("test@example.com"),
        )
        .await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-valid-key"))
            .set_json(&skr)
            .to_request();

        let key_response: SigningKeyResponse = test::call_and_read_body_json(&app, req).await;
        let pub_sign_key = key_response.pub_sign_key.unwrap();
        let id = pub_sign_key.policy.derive_ibs().unwrap();

        let message = b"message signed with api key";
        let sig = gg::Signer::new()
            .chain(message)
            .sign(&pub_sign_key.key.0, &mut rng);

        assert!(gg::Verifier::new()
            .chain(message)
            .verify(&ibs_pk, &sig, &id));
        assert!(!gg::Verifier::new()
            .chain("tampered message")
            .verify(&ibs_pk, &sig, &id));
    }

    #[actix_web::test]
    async fn test_api_key_signing_with_public_phone() {
        let (app, _) = setup_api_key_test_with_mock_store(
            "PG-valid-key".to_string(),
            ApiKeyData {
                org_id: "00000000-0000-0000-0000-000000000001".to_string(),
                email: "test@example.com".to_string(),
                organisation_name: None,
                phone_number: Some("+31612345678".to_string()),
                kvk_number: None,
                organisation_name_public: false,
                phone_number_public: true,
                kvk_number_public: false,
            },
        )
        .await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-valid-key"))
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        let key_response: SigningKeyResponse = test::try_read_body_json(resp).await.unwrap();

        let pub_key = key_response.pub_sign_key.unwrap();
        assert_eq!(pub_key.policy.con.len(), 2);
        assert!(pub_key
            .policy
            .con
            .iter()
            .any(|a| a.atype == "pbdf.sidn-pbdf.email.email"));
        assert!(pub_key
            .policy
            .con
            .iter()
            .any(|a| a.atype == "pbdf.sidn-pbdf.mobilenumber.mobilenumber"));
        assert!(key_response.priv_sign_key.is_none());
    }

    #[actix_web::test]
    async fn test_api_key_signing_with_private_phone() {
        let (app, _) = setup_api_key_test_with_mock_store(
            "PG-valid-key".to_string(),
            ApiKeyData {
                org_id: "00000000-0000-0000-0000-000000000001".to_string(),
                email: "test@example.com".to_string(),
                organisation_name: None,
                phone_number: Some("+31612345678".to_string()),
                kvk_number: None,
                organisation_name_public: false,
                phone_number_public: false,
                kvk_number_public: false,
            },
        )
        .await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-valid-key"))
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        let key_response: SigningKeyResponse = test::try_read_body_json(resp).await.unwrap();

        // Email is public
        let pub_key = key_response.pub_sign_key.unwrap();
        assert_eq!(pub_key.policy.con.len(), 1);
        assert_eq!(pub_key.policy.con[0].atype, "pbdf.sidn-pbdf.email.email");

        // Phone is private
        let priv_key = key_response.priv_sign_key.unwrap();
        assert_eq!(priv_key.policy.con.len(), 1);
        assert_eq!(
            priv_key.policy.con[0].atype,
            "pbdf.sidn-pbdf.mobilenumber.mobilenumber"
        );
    }

    #[actix_web::test]
    async fn test_api_key_signing_all_fields() {
        let (app, _) = setup_api_key_test_with_mock_store(
            "PG-valid-key".to_string(),
            ApiKeyData {
                org_id: "00000000-0000-0000-0000-000000000001".to_string(),
                email: "test@example.com".to_string(),
                organisation_name: Some("Acme Corp".to_string()),
                phone_number: Some("+31612345678".to_string()),
                kvk_number: Some("12345678".to_string()),
                organisation_name_public: true,
                phone_number_public: false,
                kvk_number_public: true,
            },
        )
        .await;

        let skr = SigningKeyRequest {
            pub_sign_id: vec![],
            priv_sign_id: None,
        };

        let req = test::TestRequest::post()
            .uri("/v2/sign/key")
            .insert_header(("Authorization", "Bearer PG-valid-key"))
            .set_json(&skr)
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        let key_response: SigningKeyResponse = test::try_read_body_json(resp).await.unwrap();

        // Public: email + organisation_name + kvk_number
        let pub_key = key_response.pub_sign_key.unwrap();
        assert_eq!(pub_key.policy.con.len(), 3);
        assert!(pub_key
            .policy
            .con
            .iter()
            .any(|a| a.atype == "pbdf.sidn-pbdf.email.email"));
        assert!(pub_key
            .policy
            .con
            .iter()
            .any(|a| a.atype == "pbdf.pbdf.kvk.displayName"));
        assert!(pub_key
            .policy
            .con
            .iter()
            .any(|a| a.atype == "pbdf.pbdf.kvk.kvkNumber"));

        // Private: phone_number only
        let priv_key = key_response.priv_sign_key.unwrap();
        assert_eq!(priv_key.policy.con.len(), 1);
        assert_eq!(
            priv_key.policy.con[0].atype,
            "pbdf.sidn-pbdf.mobilenumber.mobilenumber"
        );
    }

    async fn setup_guard_test() -> impl Service<Request, Response = ServiceResponse, Error = Error>
    {
        use actix_web::{test, web, App, HttpResponse};
        let app = test::init_service(
            App::new().service(
                resource("/api-key")
                    .guard(ApiKeyGuard)
                    .route(web::get().to(|| async { HttpResponse::Ok().body("api-key") })),
            ),
        )
        .await;

        app
    }

    #[actix_web::test]
    async fn test_signing_guard_valid_key() {
        use actix_web::test;

        let app = setup_guard_test().await;

        let req = test::TestRequest::get()
            .uri("/api-key")
            .insert_header(("Authorization", "Bearer PG-test-key"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let req = test::TestRequest::get()
            .uri("/api-key")
            .insert_header(("Authorization", "bearer PG-test-key"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_signing_guard_unprefixed_key() {
        use actix_web::test;

        let app = setup_guard_test().await;

        let req = test::TestRequest::get()
            .uri("/api-key")
            .insert_header(("Authorization", "Bearer test-key"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn test_signing_guard_no_auth_header() {
        use actix_web::test;

        let app = setup_guard_test().await;

        let req = test::TestRequest::get().uri("/api-key").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn test_signing_guard_empty_bearer() {
        use actix_web::test;

        let app = setup_guard_test().await;

        let req = test::TestRequest::get()
            .uri("/api-key")
            .insert_header(("Authorization", "Bearer "))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    async fn setup_api_key_validate_test(
        key: String,
        data: ApiKeyData,
    ) -> impl Service<Request, Response = ServiceResponse, Error = Error> {
        let irma = "https://irma.example.org".to_string();

        let mock_store = if key.is_empty() {
            MockApiKeyStore::new()
        } else {
            MockApiKeyStore::new().with_key(key, data)
        };

        test::init_service(
            App::new().service(
                scope("/v2").service(
                    resource("/api-key/validate")
                        .guard(ApiKeyGuard)
                        .wrap(Auth::new(irma.clone(), AuthType::Key).with_api_key_store(mock_store))
                        .route(web::get().to(handlers::api_key_validate)),
                ),
            ),
        )
        .await
    }

    #[actix_web::test]
    async fn test_api_key_validate_success_returns_tenant_id() {
        let mut data = default_api_key_data("test@example.com");
        data.org_id = "11111111-2222-3333-4444-555555555555".to_string();
        data.organisation_name = Some("Acme".to_string());

        let app = setup_api_key_validate_test("PG-valid-key".to_string(), data).await;

        let req = test::TestRequest::get()
            .uri("/v2/api-key/validate")
            .insert_header(("Authorization", "Bearer PG-valid-key"))
            .to_request();

        let resp = test::try_call_service(&app, req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = test::try_read_body_json(resp).await.unwrap();
        assert_eq!(body["tenant_id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(body["organisation_name"], "Acme");
    }

    #[actix_web::test]
    async fn test_api_key_validate_unknown_key_rejected() {
        let app = setup_api_key_validate_test(
            "PG-valid-key".to_string(),
            default_api_key_data("test@example.com"),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/api-key/validate")
            .insert_header(("Authorization", "Bearer PG-not-the-key"))
            .to_request();

        let resp = test::try_call_service(&app, req).await;
        assert!(resp.is_err(), "Expected error for unknown API key");
    }

    #[actix_web::test]
    async fn test_api_key_validate_missing_bearer_404() {
        // No Authorization header at all → ApiKeyGuard rejects → 404 (no
        // matching route), since the route only registers on PG-prefixed
        // bearer tokens.
        let app = setup_api_key_validate_test(
            "PG-valid-key".to_string(),
            default_api_key_data("test@example.com"),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/api-key/validate")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn test_api_key_validate_non_pg_bearer_404() {
        // A non-PG bearer (e.g. a JWT) should fall through the guard and 404,
        // not get routed into the API-key validator.
        let app = setup_api_key_validate_test(
            "PG-valid-key".to_string(),
            default_api_key_data("test@example.com"),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v2/api-key/validate")
            .insert_header(("Authorization", "Bearer eyJhbGc.notapgkey"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ---------------------------------------------------------------------
    // Rate-limiting (actix-governor) integration tests
    // ---------------------------------------------------------------------

    use actix_governor::{Governor, GovernorConfigBuilder};
    use actix_web::http::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// A `/v2` scope mirroring the production middleware stack: a general
    /// governor on the whole scope, a stricter governor on the `/key`
    /// endpoint, and one unlimited endpoint reachable only via the general
    /// limit. The replenish rate is kept at 1/s so the bucket does not refill
    /// while a test fires its requests back-to-back within a few milliseconds.
    async fn ratelimit_setup(
        general_burst: u32,
        sensitive_burst: u32,
        permissive: bool,
    ) -> impl Service<Request, Response = ServiceResponse, Error = Error> {
        let mut rng = thread_rng();
        let (ibe_pk, ibe_sk) = CGWKV::setup(&mut rng);

        let pd = ParametersData::new(
            &Parameters::<PublicKey<CGWKV>> {
                format_version: 0x00,
                public_key: PublicKey(ibe_pk),
            },
            None,
        )
        .unwrap();

        let make_config = |burst: u32| {
            let mut builder = GovernorConfigBuilder::default();
            builder.requests_per_second(1).burst_size(burst.max(1));
            builder
                .const_permissive(permissive)
                .finish()
                .expect("invalid rate-limit configuration")
        };
        let general = make_config(general_burst);
        let sensitive = make_config(sensitive_burst);

        test::init_service(
            App::new().service(
                scope("/v2")
                    .wrap(Governor::new(&general))
                    .service(
                        resource("/parameters")
                            .app_data(Data::new(pd))
                            .route(web::get().to(handlers::parameters)),
                    )
                    .service(
                        resource("/key")
                            .app_data(Data::new(ibe_sk))
                            .wrap(NoAuth::Decryption)
                            .wrap(Governor::new(&sensitive))
                            .route(web::get().to(handlers::key::<CGWKV>)),
                    ),
            ),
        )
        .await
    }

    fn peer(last_octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last_octet)), 4000)
    }

    fn key_request(peer_addr: SocketAddr) -> Request {
        let pol = Policy {
            timestamp: now(),
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };
        test::TestRequest::get()
            .uri("/v2/key")
            .peer_addr(peer_addr)
            .set_json(pol)
            .to_request()
    }

    #[actix_web::test]
    async fn test_ratelimit_sensitive_endpoint_returns_429() {
        // General limit is generous; the sensitive limit (burst 2) is what
        // should trip on the `/key` endpoint.
        let app = ratelimit_setup(100, 2, false).await;
        let ip = peer(10);

        // First two requests fit within the burst.
        for i in 0..2 {
            let resp = test::call_service(&app, key_request(ip)).await;
            assert_eq!(resp.status(), 200, "request {i} should be allowed");
        }

        // Third request exceeds the sensitive burst → 429.
        let resp = test::call_service(&app, key_request(ip)).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key("retry-after"),
            "429 response must carry a retry-after header"
        );
    }

    #[actix_web::test]
    async fn test_ratelimit_is_per_ip() {
        let app = ratelimit_setup(100, 2, false).await;

        // Exhaust the sensitive burst for IP .20.
        for _ in 0..2 {
            let resp = test::call_service(&app, key_request(peer(20))).await;
            assert_eq!(resp.status(), 200);
        }
        let resp = test::call_service(&app, key_request(peer(20))).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different IP still has its own fresh bucket.
        let resp = test::call_service(&app, key_request(peer(21))).await;
        assert_eq!(
            resp.status(),
            200,
            "a different peer IP must not be throttled by another IP's usage"
        );
    }

    #[actix_web::test]
    async fn test_ratelimit_general_scope_returns_429() {
        // Sensitive limit is generous; the general scope limit (burst 2) is
        // what should trip on the otherwise-unlimited `/parameters` endpoint.
        let app = ratelimit_setup(2, 100, false).await;
        let ip = peer(30);

        for i in 0..2 {
            let req = test::TestRequest::get()
                .uri("/v2/parameters")
                .peer_addr(ip)
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200, "request {i} should be allowed");
        }

        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .peer_addr(ip)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[actix_web::test]
    async fn test_ratelimit_permissive_never_blocks() {
        // With `--ratelimit-disabled` the middleware is built in permissive
        // mode and must pass every request through, even well past the burst.
        let app = ratelimit_setup(1, 1, true).await;
        let ip = peer(40);

        for i in 0..10 {
            let resp = test::call_service(&app, key_request(ip)).await;
            assert_eq!(
                resp.status(),
                200,
                "permissive mode must never return 429 (request {i})"
            );
        }
    }

    /// A request with a misspelled field must be a 400 in the documented
    /// `{error, message}` envelope, with the message naming the field — not
    /// silently accepted (deny_unknown_fields), and not actix's default
    /// plain-text error body.
    #[actix_web::test]
    async fn test_unknown_request_field_yields_400_envelope() {
        use pg_core::api::IrmaAuthRequest;

        let app = test::init_service(App::new().app_data(Data::new(json_config())).service(
            resource("/echo").route(web::post().to(|_body: web::Json<IrmaAuthRequest>| async {
                actix_web::HttpResponse::Ok().finish()
            })),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/echo")
            .insert_header(("Content-Type", "application/json"))
            .set_payload(r#"{ "con": [ { "t": "pbdf.sidn-pbdf.email.email", "vaule": "x" } ] }"#)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], serde_json::Value::Bool(true));
        let msg = body["message"].as_str().expect("message must be a string");
        assert!(
            msg.contains("vaule"),
            "the 400 must name the unknown field, got: {msg}"
        );
    }
}
