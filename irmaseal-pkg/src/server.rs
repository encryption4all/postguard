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

    let kp2 = MasterKeyPair::<CGWKV> {
        pk: cgwkv_read_pk(public).unwrap(),
        sk: cgwkv_read_sk(secret).unwrap(),
    };

    System::new().block_on(async move {
        actix_web::HttpServer::new(move || {
            actix_web::App::new()
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
