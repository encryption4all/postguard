use crate::server::MasterKeyPair;
use actix_web::{
    web::{Data, HttpResponse},
    Responder,
};
use futures::future::{ready, Future, Ready};
use ibe::kem::IBKEM;
use irmaseal_core::{api::Parameters, PublicKey};

struct WrappedParameters<K: IBKEM>(Parameters<K>);

impl<K: IBKEM> Responder for WrappedParameters<K> {
    type Error = crate::Error;
    type Future = Ready<Result<HttpResponse, crate::Error>>;

    fn respond_to(self, req: &actix_web::HttpRequest) -> Self::Future {
        ready(Ok(HttpResponse::Ok().json(self.0)))
    }
}

pub async fn parameters<K: IBKEM>(
    data: Data<(String, MasterKeyPair<K>)>,
) -> impl Future<Output = Result<HttpResponse, crate::Error>> {
    let (_, kp) = data.get_ref().clone();

    let pars = Parameters {
        format_version: 0x00,
        max_age: 300,
        public_key: PublicKey::<K>(kp.pk),
    };

    ready(Ok(HttpResponse::Ok().json(pars)))
}
