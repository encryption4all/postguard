use std::str::FromStr;
use std::time::SystemTime;

use actix_http::header::HttpDate;
use actix_web::http::header::EntityTag;
use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{api::Parameters, PublicKey};

use crate::handlers;
use crate::opts::*;
use crate::util::*;
use actix_cors::Cors;
use actix_web::{
    http::header,
    web,
    web::{resource, scope, Data},
    App, HttpServer,
};

use crate::middleware::irma::{IrmaAuth, IrmaAuthType};

#[derive(Clone)]
pub struct MasterKeyPair<K: IBKEM> {
    pub pk: K::Pk,
    pub sk: K::Sk,
}

#[derive(Clone)]
pub struct ParametersData {
    pub pp: String,
    pub last_modified: HttpDate,
    pub etag: EntityTag,
}

#[actix_rt::main]
pub async fn exec(server_opts: ServerOpts) {
    let ServerOpts {
        host,
        port,
        irma,
        secret,
        public,
    } = server_opts;

    let kp = MasterKeyPair::<CGWKV> {
        pk: cgwkv_read_pk(&public).expect("cannot read public key"),
        sk: cgwkv_read_sk(&secret).expect("cannot read secret key"),
    };

    // Precompute the serialized public parameters.
    let pp = serde_json::to_string(&Parameters::<CGWKV> {
        format_version: 0x00,
        public_key: PublicKey(kp.pk),
    })
    .expect("could not serialize public parameters");

    // Also compute cache headers.
    let modified_raw: HttpDate = match std::fs::metadata(&public).map(|m| m.modified()) {
        Ok(Ok(t)) => t,
        _ => SystemTime::now(),
    }
    .into();
    let last_modified = HttpDate::from_str(&modified_raw.to_string()).unwrap();

    let etag = EntityTag::new_strong(xxhash64(pp.as_bytes()));

    let pd = ParametersData {
        pp,
        last_modified,
        etag,
    };

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_header(header::CONTENT_TYPE)
                    .allowed_header(header::AUTHORIZATION)
                    .allowed_header(header::ETAG)
                    .allowed_header("X-Postguard-Client-Version")
                    .max_age(86400),
            )
            .app_data(Data::new(web::JsonConfig::default().limit(1024 * 4096)))
            .service(
                scope("/v2")
                    .service(
                        resource("/parameters")
                            .app_data(Data::new(pd.clone()))
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
                                    .app_data(Data::new(kp.sk))
                                    .wrap(IrmaAuth::<CGWKV>::new(irma.clone(), IrmaAuthType::Jwt))
                                    .route(web::get().to(handlers::request_key::<CGWKV>)),
                            ),
                    ),
            )
    })
    .bind(format!("{}:{}", host, port))
    .unwrap()
    .shutdown_timeout(1)
    .run()
    .await
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::irma_noauth::NoAuth;
    use actix_http::Request;
    use actix_web::dev::{Service, ServiceResponse};
    use actix_web::{test, web, App, Error};
    use irma::{ProofStatus, SessionStatus};
    use irmaseal_core::api::{KeyResponse, Parameters};
    use irmaseal_core::{Attribute, Policy};
    use rand::thread_rng;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn default_setup() -> (
        impl Service<Request, Response = ServiceResponse, Error = Error>,
        <CGWKV as IBKEM>::Pk,
        <CGWKV as IBKEM>::Sk,
    ) {
        let mut rng = thread_rng();
        let (pk, sk) = CGWKV::setup(&mut rng);

        // Precompute the serialized public parameters.
        let pp = serde_json::to_string(&Parameters::<CGWKV> {
            format_version: 0x00,
            public_key: PublicKey(pk),
        })
        .expect("could not serialize public parameters");
        let last_modified = SystemTime::now();
        let etag = EntityTag::new_strong(xxhash64(pp.as_bytes()));

        let pd = ParametersData {
            pp,
            last_modified,
            etag,
        };

        // Create a simple setup with a pk endpoint and a key service without authentication.
        let app = test::init_service(
            App::new().service(
                scope("/v2")
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

        let req = test::TestRequest::get().uri("/v2/parameters").to_request();
        let kr: Parameters<CGWKV> = test::call_and_read_body_json(&app, req).await;

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
