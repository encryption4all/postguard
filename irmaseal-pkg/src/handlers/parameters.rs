use crate::server::MasterKeyPair;
use actix_web::web::{Data, HttpResponse};
use futures::future::{ok, Future};
use ibe::kem::IBKEM;
use irmaseal_core::{api::Parameters, PublicKey};

pub fn parameters<K: IBKEM>(
    state: Data<(String, MasterKeyPair<K>)>,
) -> impl Future<Item = HttpResponse, Error = crate::Error> {
    let (_, kp) = state.get_ref().clone();
    let parameters = Parameters {
        format_version: 0x00,
        max_age: 300,
        public_key: PublicKey::<K>(kp.pk),
    };

    ok(HttpResponse::Ok().json(parameters))
}
