use irmaseal_core::kem::IBKEM;
use irmaseal_core::{api::*, PublicKey};
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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
    pub fn new(baseurl: &'a str) -> Result<Client, ClientError> {
        let client = ClientBuilder::new().build()?;

        Ok(Client { baseurl, client })
    }

    fn create_url(&self, u: &str) -> Url {
        Url::parse(self.baseurl).unwrap().join(u).unwrap()
    }

    pub async fn parameters<K>(&self) -> Result<Parameters<K>, ClientError>
    where
        K: IBKEM,
        PublicKey<K>: DeserializeOwned,
    {
        self.client
            .get(self.create_url("v2/parameters"))
            .send()
            .await?
            .error_for_status()?
            .json::<Parameters<K>>()
            .await
    }

    pub async fn request_start(&self, kr: &KeyRequest) -> Result<irma::SessionData, ClientError> {
        self.client
            .post(self.create_url("v2/irma/start"))
            .json(kr)
            .send()
            .await?
            .error_for_status()?
            .json::<irma::SessionData>()
            .await
    }

    pub async fn request_jwt(&self, token: &irma::SessionToken) -> Result<String, ClientError> {
        self.client
            .get(self.create_url(&format!("v2/irma/jwt/{}", token.0)))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }

    pub async fn request_key<K>(
        &self,
        timestamp: u64,
        auth: &str,
    ) -> Result<KeyResponse<K>, ClientError>
    where
        K: IBKEM,
        KeyResponse<K>: DeserializeOwned,
    {
        self.client
            .get(self.create_url(&format!("v2/irma/key/{timestamp}")))
            .bearer_auth(auth)
            .send()
            .await?
            .error_for_status()?
            .json::<KeyResponse<K>>()
            .await
    }
}
