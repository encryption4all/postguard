use actix_web::web::{Data, HttpResponse, Json};
use actix_web::Responder;
use futures::future::{ready, Ready};
use ibe::kem::IBKEM;
use irmaseal_core::api::{KeyChallenge, KeyRequest};

use irma::client::Client;
use irma::request::*;

use crate::server::MasterKeyPair;

struct WrappedKeyChallenge<'a>(KeyChallenge<'a>);

impl<'a> Responder for WrappedKeyChallenge<'a> {
    type Error = crate::Error;
    type Future = Ready<Result<HttpResponse, crate::Error>>;

    fn respond_to(self, req: &actix_web::HttpRequest) -> Self::Future {
        ready(Ok(HttpResponse::Ok().json(self.0)))
    }
}

pub async fn request<K: IBKEM>(
    state: Data<(String, MasterKeyPair<K>)>,
    value: Json<KeyRequest>,
) -> impl Responder {
    let (irma_url, _) = state.get_ref().clone();

    let kr = value.into_inner();
    let a = kr.attribute;

    let dr = DisclosureRequest {
        disclose: AttributeConDisCon(vec![AttributeDisCon(vec![AttributeCon(vec![
            AttributeRequest {
                atype: a.atype.to_string(),
                value: a.value.map(|s| s.to_string()),
                not_null: true,
            },
        ])])]),
        labels: None,
    };

    let client = Client::new(irma_url.clone()).unwrap();

    //    client.request(&dr).then(move |sp| {
    //        let sp = sp.or(Err(crate::Error::UpstreamError))?;
    //
    //        let qr = &serde_json::to_string(&sp.session_ptr).or(Err(crate::Error::Unexpected))?;
    //        let token: &str = (&sp.token).into();
    //
    //        Ok(HttpResponse::Ok().json(KeyChallenge { qr, token }))
    //    })
    //
    WrappedKeyChallenge(KeyChallenge {
        qr: &"bla",
        token: &"bla",
    })
}
