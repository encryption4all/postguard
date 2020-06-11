use actix_web::web::{Data, HttpResponse, Json};
use futures::future::Future;
use irmaseal_core::api::{KeyChallenge, KeyRequest};

use irma::client::Client;
use irma::request::*;

use crate::server::AppState;

pub fn request_preflight(
) -> Result<HttpResponse, crate::Error> {
    let response = HttpResponse::Ok()
        .header("Access-Control-Allow-Methods", "POST")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .header("Access-Control-Allow-Origin", "*")
        .finish();
    Ok(response)
}

pub fn request(
    state: Data<AppState>,
    value: Json<KeyRequest>,
) -> impl Future<Item = HttpResponse, Error = crate::Error> {
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

    let client = Client::new(state.irma_server_host.clone()).unwrap();

    client.request(&dr).then(move |sp| {
        let sp = sp.or(Err(crate::Error::UpstreamError))?;

        let qr = &serde_json::to_string(&sp.session_ptr).or(Err(crate::Error::Unexpected))?;
        let token: &str = (&sp.token).into();

        Ok(HttpResponse::Ok().header("Access-Control-Allow-Origin", "*").json(KeyChallenge { qr, token }))
    })
}
