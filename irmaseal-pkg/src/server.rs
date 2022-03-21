use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::IBKEM;
use jsonwebtoken::DecodingKey;

use crate::handlers;
use crate::opts::*;
use crate::util::*;
use actix_cors::Cors;
use actix_rt::System;
use actix_web::{
    http::header,
    web,
    web::{resource, scope, Data},
};

#[derive(Clone)]
pub struct MasterKeyPair<K: IBKEM> {
    pub pk: K::Pk,
    pub sk: K::Sk,
}

pub fn exec(server_opts: ServerOpts) {
    let ServerOpts {
        host,
        port,
        irma,
        secret,
        public,
    } = server_opts;

    let kp = MasterKeyPair::<CGWKV> {
        pk: cgwkv_read_pk(public).unwrap(),
        sk: cgwkv_read_sk(secret).unwrap(),
    };

    System::new().block_on(async move {
        let jwt_pk_bytes = reqwest::get(&format!("{irma}/publickey"))
            .await
            .expect("could not retrieve JWT public key")
            .bytes()
            .await
            .expect("could not retrieve JWT public key bytes");

        let decoding_key =
            DecodingKey::from_rsa_pem(&jwt_pk_bytes).expect("could not parse JWT public key");

        actix_web::HttpServer::new(move || {
            actix_web::App::new()
                .wrap(
                    Cors::default()
                        .allow_any_origin()
                        .allowed_methods(vec!["GET", "POST"])
                        .allowed_header(header::CONTENT_TYPE)
                        .allowed_header(header::AUTHORIZATION)
                        .max_age(3600),
                )
                .app_data(Data::new(
                    actix_web::web::JsonConfig::default().limit(1024 * 4096),
                ))
                .service(
                    scope("/v2")
                        .service(
                            resource("/parameters")
                                .app_data(Data::new(kp.pk))
                                .route(web::get().to(handlers::parameters::<CGWKV>)),
                        )
                        .service(
                            resource("/request/start")
                                .app_data(Data::new(irma.clone()))
                                .route(web::post().to(handlers::request)),
                        )
                        .service(
                            resource("/request/jwt/{token}")
                                .app_data(Data::new(irma.clone()))
                                .route(web::get().to(handlers::request_jwt)),
                        )
                        .service(
                            resource("/request/key/{timestamp}")
                                .app_data(Data::new(kp.sk))
                                .app_data(Data::new(decoding_key.clone()))
                                .route(web::get().to(handlers::request_key::<CGWKV>)),
                        ),
                )
        })
        .bind(format!("{}:{}", host, port))
        .unwrap()
        .shutdown_timeout(1)
        .run()
        .await
        .unwrap()
    })
}
