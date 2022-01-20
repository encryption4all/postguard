use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::IBKEM;

use crate::handlers;
use crate::opts::*;
use crate::util::*;
use actix_rt::System;
use actix_web::{
    web,
    web::{resource, scope, Data},
};

#[cfg(feature = "v1")]
use irmaseal_core::kem::kiltz_vahlis_one::KV1;

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
        #[cfg(feature = "v1")]
        v1secret,
        #[cfg(feature = "v1")]
        v1public,
    } = server_opts;

    #[cfg(feature = "v1")]
    let kp1 = MasterKeyPair::<KV1> {
        pk: kv1_read_pk(v1public).unwrap(),
        sk: kv1_read_sk(v1secret).unwrap(),
    };

    let kp2 = MasterKeyPair::<CGWKV> {
        pk: cgwkv_read_pk(public).unwrap(),
        sk: cgwkv_read_sk(secret).unwrap(),
    };

    System::new().block_on(async move {
        actix_web::HttpServer::new(move || {
            let app = actix_web::App::new()
                .wrap(actix_cors::Cors::permissive())
                .app_data(Data::new(
                    actix_web::web::JsonConfig::default().limit(1024 * 4096),
                ))
                .service(
                    scope("/v2")
                        .app_data(Data::new(irma.clone()))
                        .service(
                            resource("/parameters")
                                .app_data(Data::new(kp2.pk.clone()))
                                .route(web::get().to(handlers::parameters::<CGWKV>)),
                        )
                        .service(resource("/request").route(web::post().to(handlers::request)))
                        .service(
                            resource("/request/{token}/{timestamp}")
                                .app_data(Data::new(kp2.clone()))
                                .route(web::get().to(handlers::request_fetch::<CGWKV>)),
                        ),
                );

            #[cfg(feature = "v1")]
            let app = app.service(
                scope("/v1")
                    .app_data(Data::new(irma.clone()))
                    .service(
                        resource("/parameters")
                            .app_data(Data::new(kp1.pk.clone()))
                            .route(web::get().to(handlers::parameters::<KV1>)),
                    )
                    .service(resource("/request").route(web::post().to(handlers::request)))
                    .service(
                        resource("/request/{token}/{timestamp}")
                            .app_data(Data::new(kp1.clone()))
                            .route(web::get().to(handlers::request_fetch::<KV1>)),
                    ),
            );

            app
        })
        .bind(format!("{}:{}", host, port))
        .unwrap()
        .shutdown_timeout(1)
        .run()
        .await
        .unwrap()
    })
}
