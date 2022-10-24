use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::IBKEM;
use jsonwebtoken::DecodingKey;

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

#[derive(Clone)]
pub struct MasterKeyPair<K: IBKEM> {
    pub pk: K::Pk,
    pub sk: K::Sk,
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
        pk: cgwkv_read_pk(public).unwrap(),
        sk: cgwkv_read_sk(secret).unwrap(),
    };

    let jwt_pk_bytes = reqwest::get(&format!("{irma}/publickey"))
        .await
        .expect("could not retrieve JWT public key")
        .bytes()
        .await
        .expect("could not retrieve JWT public key bytes");

    let decoding_key =
        DecodingKey::from_rsa_pem(&jwt_pk_bytes).expect("could not parse JWT public key");

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_header(header::CONTENT_TYPE)
                    .allowed_header(header::AUTHORIZATION)
                    .allowed_header("X-Postguard-Client-Version")
                    .max_age(86400),
            )
            .app_data(Data::new(web::JsonConfig::default().limit(1024 * 4096)))
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
}
