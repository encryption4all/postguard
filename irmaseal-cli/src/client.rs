use futures::future::Future;
use reqwest::r#async::ClientBuilder;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use irmaseal_core::api::*;

pub struct Client<'a> {
    baseurl: &'a str,
    client: reqwest::r#async::Client,
}

pub type ClientError = reqwest::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct OwnedKeyChallenge {
    pub qr: String,
    pub token: String,
}

impl<'a> Client<'a> {
    pub fn new(baseurl: &'a str) -> Result<Client, reqwest::Error> {
        let client = ClientBuilder::new().build().unwrap();

        Ok(Client { baseurl, client })
    }

    fn create_url(&self, u: &str) -> Url {
        Url::parse(&self.baseurl).unwrap().join(u).unwrap()
    }

    pub fn parameters(&self) -> impl Future<Item = Parameters, Error = ClientError> {
        self.client
            .get(self.create_url("/v1/parameters"))
            .send()
            .and_then(|mut resp| resp.json::<Parameters>())
    }

    pub fn request(
        &self,
        kr: &KeyRequest,
    ) -> impl Future<Item = OwnedKeyChallenge, Error = ClientError> {
        self.client
            .post(self.create_url("/v1/request"))
            .json(kr)
            .send()
            .and_then(|resp| resp.error_for_status())
            .and_then(|mut resp| resp.json::<OwnedKeyChallenge>())
    }

    pub fn result(
        &self,
        token: &str,
        timestamp: u64,
    ) -> impl Future<Item = KeyResponse, Error = ClientError> {
        self.client
            .get(
                self.create_url("/v1/request/")
                    .join(&format!("{}/{}", token, timestamp))
                    .unwrap(),
            )
            .send()
            .and_then(|resp| resp.error_for_status())
            .and_then(|mut resp| resp.json::<KeyResponse>())
    }
}
