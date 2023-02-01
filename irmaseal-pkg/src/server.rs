use crate::handlers;
use crate::middleware::irma::{IrmaAuth, IrmaAuthType};
use crate::middleware::metrics::collect_metrics;
use crate::opts::*;
use crate::util::*;
use actix_cors::Cors;
use actix_http::header::HttpDate;
use actix_web::http::header::EntityTag;
use actix_web::{
    http::header,
    middleware::Logger,
    web,
    web::{resource, scope, Data},
    App, HttpServer,
};
use irmaseal_core::api::Parameters;
use irmaseal_core::ibs::gg;
use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::PublicKey;
use lazy_static::lazy_static;
use prometheus::{register_int_counter_vec, IntCounterVec};

lazy_static! {
    pub(crate) static ref POSTGUARD_CLIENTS: IntCounterVec = register_int_counter_vec!(
        "postguard_clients",
        "Contains information about PostGuard clients connecting with the PKG.",
        &["path", "host", "host_version", "client", "client_version"]
    )
    .unwrap();
}

#[derive(Clone)]
pub struct MasterKeyPair<K: IBKEM> {
    pub pk: K::Pk,
    pub sk: K::Sk,
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
pub async fn exec(server_opts: ServerOpts) {
    let ServerOpts {
        host,
        port,
        irma,
        ibe_secret,
        ibe_public,
        ibs_secret,
        ibs_public,
    } = server_opts;

    let ibe_kp = MasterKeyPair::<CGWKV> {
        pk: cgwkv_read_pk(&ibe_public).expect("cannot read public key from disk"),
        sk: cgwkv_read_sk(&ibe_secret).expect("cannot read secret key from disk"),
    };

    let ibe_pd = ParametersData::new(
        &Parameters::<CGWKV> {
            format_version: 0x00,
            public_key: PublicKey::<CGWKV>(ibe_kp.pk),
        },
        Some(&ibe_public),
    );

    let ibs_pk: gg::PublicKey =
        rmp_serde::from_slice(&std::fs::read(&ibs_public).unwrap()).unwrap();
    let ibs_pd = ParametersData::new(&ibs_pk, Some(&ibs_public));

    let ibs_sk: gg::SecretKey =
        rmp_serde::from_slice(&std::fs::read(&ibs_secret).unwrap()).unwrap();

    dbg!(&ibs_pd);

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    HttpServer::new(move || {
        App::new()
            .wrap(
                Logger::new(
                    "request=%{PATH}xi, status=%s, client=%{CLIENT_ID}xi, response_time=%D ms",
                )
                .custom_request_replace("CLIENT_ID", client_version)
                .custom_request_replace("PATH", |req| {
                    req.match_pattern().unwrap_or("-".to_string())
                }),
            )
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_header(header::CONTENT_TYPE)
                    .allowed_header(header::AUTHORIZATION)
                    .allowed_header(header::ETAG)
                    .allowed_header(PG_CLIENT_HEADER)
                    .max_age(86400),
            )
            .service(resource("/metrics").route(web::get().to(handlers::metrics)))
            .service(
                scope("/v2")
                    .wrap_fn(collect_metrics)
                    .app_data(Data::new(web::JsonConfig::default().limit(1024 * 4096)))
                    .service(
                        resource("/parameters")
                            .app_data(Data::new(ibe_pd.clone()))
                            .route(web::get().to(handlers::parameters)),
                    )
                    .service(
                        resource("/sign/parameters")
                            .app_data(Data::new(ibs_pd.clone()))
                            .route(web::get().to(handlers::parameters)),
                    )
                    .service(
                        scope("/{_:(irma|request)}")
                            .service(
                                resource("/start")
                                    .app_data(Data::new(irma.clone()))
                                    .route(web::post().to(handlers::request)),
                            )
                            .service(
                                resource("/jwt/{token}")
                                    .app_data(Data::new(irma.clone()))
                                    .route(web::get().to(handlers::request_jwt)),
                            )
                            .service(
                                resource("/key/{timestamp}")
                                    .app_data(Data::new(ibe_kp.sk))
                                    .wrap(IrmaAuth::new(irma.clone(), IrmaAuthType::Jwt))
                                    .route(web::get().to(handlers::request_key::<CGWKV>)),
                            )
                            .service(
                                resource("/sign/key")
                                    .app_data(Data::new(ibs_sk))
                                    .wrap(IrmaAuth::new(irma.clone(), IrmaAuthType::Jwt))
                                    .route(web::get().to(handlers::request_signing_key)),
                            ),
                    ),
            )
    })
    .bind(format!("{host}:{port}"))
    .unwrap()
    .shutdown_timeout(1)
    .run()
    .await
    .unwrap();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::middleware::irma_noauth::NoAuth;
    use actix_http::Request;
    use actix_web::dev::{Service, ServiceResponse};
    use actix_web::{test, web, App, Error};
    use irma::{ProofStatus, SessionStatus};
    use irmaseal_core::api::{KeyResponse, Parameters};
    use irmaseal_core::{Attribute, Policy};
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
    ) {
        let mut rng = thread_rng();
        let (pk, sk) = CGWKV::setup(&mut rng);

        let pd = ParametersData::new(&pk, None);

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
                            resource("/key/{timestamp}")
                                .app_data(Data::new(sk))
                                .wrap(NoAuth::<CGWKV>::new())
                                .route(web::get().to(handlers::request_key::<CGWKV>)),
                        ),
                ),
        )
        .await;

        (app, pk, sk)
    }

    #[actix_web::test]
    async fn test_get_parameters() {
        let (app, pk, _) = default_setup().await;

        let resp = test::TestRequest::get()
            .uri("/v2/parameters")
            .send_request(&app)
            .await;

        assert!(resp.headers().contains_key("last-modified"));
        assert!(resp.headers().contains_key("cache-control"));
        assert!(resp.headers().contains_key("etag"));

        let kr: Parameters<CGWKV> = test::read_body_json(resp).await;
        assert_eq!(&kr.public_key.0, &pk);
        assert_eq!(kr.format_version, 0x00);
    }

    #[actix_web::test]
    async fn test_get_usk() {
        let (app, _, _) = default_setup().await;

        let ts = now();

        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let req = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol.clone())
            .to_request();

        let key_response: KeyResponse<CGWKV> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(key_response.status, SessionStatus::Done);
        assert_eq!(key_response.proof_status, Some(ProofStatus::Valid));
    }

    #[actix_web::test]
    async fn test_round() {
        let mut rng = thread_rng();
        let (app, _, sk) = default_setup().await;

        let ts = now();

        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let id = pol.derive::<CGWKV>().unwrap();

        let req_pk = test::TestRequest::get().uri("/v2/parameters").to_request();
        let ppk: Parameters<CGWKV> = test::call_and_read_body_json(&app, req_pk).await;

        // Encapsulate a shared secret using the MPK from the PKG API.
        let (ct, ss1) = CGWKV::encaps(&ppk.public_key.0, &id, &mut rng);

        let req_usk = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol.clone())
            .to_request();

        let key_response: KeyResponse<CGWKV> = test::call_and_read_body_json(&app, req_usk).await;

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
    async fn test_wrong_policy() {
        let mut rng = thread_rng();
        let (app, _, _) = default_setup().await;

        let ts = now();

        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };

        let id = pol.derive::<CGWKV>().unwrap();

        let req_pk = test::TestRequest::get().uri("/v2/parameters").to_request();
        let ppk: Parameters<CGWKV> = test::call_and_read_body_json(&app, req_pk).await;

        // Encapsulate a shared secret for pol using the MPK from the PKG API.
        let (ct, ss1) = CGWKV::encaps(&ppk.public_key.0, &id, &mut rng);

        let req_usk = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .set_json(pol.clone())
            .to_request();

        let key_response: KeyResponse<CGWKV> = test::call_and_read_body_json(&app, req_usk).await;

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

        let key_response_wrong: KeyResponse<CGWKV> =
            test::call_and_read_body_json(&app, req_usk_wrong).await;

        // Make sure a USK retrieved for a different policy cannot decapsulate.
        let ss4 = CGWKV::decaps(None, &key_response_wrong.key.unwrap().0, &ct).unwrap();
        assert_ne!(ss1, ss4);
    }
}
