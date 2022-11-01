use irmaseal_core::kem::IBKEM;
use irmaseal_core::{api::*, PublicKey};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

lazy_static! {
    static ref HEADER_VAL: String = format!("unknown,unknown,cli,{PKG_VERSION}");
    static ref HEADERS: HeaderMap = {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Postguard-Client-Version",
            HeaderValue::from_static(&HEADER_VAL),
        );
        headers
    };
}

pub struct Client<'a> {
    baseurl: &'a str,
    client: reqwest::Client,
}

#[derive(Debug)]
pub enum ClientError {
    Timeout,
    Reqwest(reqwest::Error),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Reqwest(e)
    }
}

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
        Ok(self
            .client
            .get(self.create_url("v2/parameters"))
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<Parameters<K>>()
            .await?)
    }

    pub async fn request_start(&self, kr: &KeyRequest) -> Result<irma::SessionData, ClientError> {
        Ok(self
            .client
            .post(self.create_url("v2/irma/start"))
            .headers(HEADERS.clone())
            .json(kr)
            .send()
            .await?
            .error_for_status()?
            .json::<irma::SessionData>()
            .await?)
    }

    pub async fn request_jwt(&self, token: &irma::SessionToken) -> Result<String, ClientError> {
        Ok(self
            .client
            .get(self.create_url(&format!("v2/irma/jwt/{}", token.0)))
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
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
        Ok(self
            .client
            .get(self.create_url(&format!("v2/irma/key/{timestamp}")))
            .bearer_auth(auth)
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<KeyResponse<K>>()
            .await?)
    }
}
