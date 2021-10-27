use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;

use crate::handlers;
use crate::opts::*;
use crate::util::*;
use actix_rt::System;
use actix_web::web;

#[cfg(feature = "v1")]
use ibe::kem::kiltz_vahlis_one::KV1;

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

    let kp2 = MasterKeyPair::<CGWFO> {
        pk: cgwfo_read_pk(public).unwrap(),
        sk: cgwfo_read_sk(secret).unwrap(),
    };

    let sys = System::new().block_on(async {
        actix_web::HttpServer::new(move || {
            let app = actix_web::App::new()
                .wrap(actix_cors::Cors::default())
                .service(
                    web::scope("/v2/")
                        .data(actix_web::web::JsonConfig::default().limit(1024 * 4096))
                        .data((irma.clone(), kp2.clone()))
                        .service(
                            web::resource("parameters")
                                .route(web::get().to(handlers::parameters::<CGWFO>)),
                        )
//                        .service(
//                            web::resource("request")
//                                .route(web::post().to(handlers::request::<CGWFO>)),
//                        )
//                        .service(
//                            web::resource("request/{token}/{timestamp}")
//                                .route(web::get().to(handlers::request_fetch::<CGWFO>)),
//                        ),
                );

            #[cfg(feature = "v1")]
            let app = app.service(
                web::scope("/v1/")
                    .data((irma.clone(), kp1.clone()))
                    .service(
                        web::resource("parameters")
                            .route(web::get().to(handlers::parameters::<KV1>)),
                    )
                    .service(
                        web::resource("request").route(web::post().to(handlers::request::<KV1>)),
                    )
                    .service(
                        web::resource("request/{token}/{timestamp}")
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
    });
}
