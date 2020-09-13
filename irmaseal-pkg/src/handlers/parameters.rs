use crate::server::AppState;
use actix_web::web::{Data, HttpResponse};
use futures::future::{ok, Future};
use irmaseal_core::api::Parameters;

pub fn parameters(state: Data<AppState>) -> impl Future<Item = HttpResponse, Error = crate::Error> {
    let parameters = Parameters {
        format_version: 0x00,
        max_age: 300,
        public_key: state.pk.into(),
    };

    ok(HttpResponse::Ok().json(parameters))
}
