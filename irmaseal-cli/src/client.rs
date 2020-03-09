use reqwest::{ClientBuilder, Url};
use serde::{Deserialize, Serialize};

use irmaseal_core::api::*;

pub struct Client<'a> {
    baseurl: &'a str,
    client: reqwest::Client,
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

    pub async fn parameters(&self) -> Result<Parameters, ClientError> {
        self.client
            .get(self.create_url("/v1/parameters"))
            .send()
            .await?
            .error_for_status()?
            .json::<Parameters>()
            .await
    }

    pub async fn request(&self, kr: &KeyRequest) -> Result<OwnedKeyChallenge, ClientError> {
        self.client
            .post(self.create_url("/v1/request"))
            .json(kr)
            .send()
            .await?
            .error_for_status()?
            .json::<OwnedKeyChallenge>()
            .await
    }

    pub async fn result(&self, token: &str, timestamp: u64) -> Result<KeyResponse, ClientError> {
        self.client
            .get(
                self.create_url("/v1/request/")
                    .join(&format!("{}/{}", token, timestamp))
                    .unwrap(),
            )
            .send()
            .await?
            .error_for_status()?
            .json::<KeyResponse>()
            .await
    }
}
