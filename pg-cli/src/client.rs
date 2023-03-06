use pg_core::api::*;
use pg_core::artifacts::{PublicKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use pg_core::kem::IBKEM;

use pg_core::kem::cgw_kv::CGWKV;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::delay_for;

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

    pub async fn parameters<K>(&self) -> Result<Parameters<PublicKey<K>>, ClientError>
    where
        K: IBKEM,
        PublicKey<K>: DeserializeOwned,
    {
        let res = self
            .client
            .get(self.create_url("v2/parameters"))
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<Parameters<PublicKey<K>>>()
            .await?;

        Ok(res)
    }

    pub async fn signing_parameters(&self) -> Result<Parameters<VerifyingKey>, ClientError> {
        let res = self
            .client
            .get(self.create_url("v2/sign/parameters"))
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<Parameters<VerifyingKey>>()
            .await?;

        Ok(res)
    }

    pub async fn request_start(
        &self,
        kr: &IrmaAuthRequest,
    ) -> Result<irma::SessionData, ClientError> {
        let res = self
            .client
            .post(self.create_url("v2/irma/start"))
            .headers(HEADERS.clone())
            .json(kr)
            .send()
            .await?
            .error_for_status()?
            .json::<irma::SessionData>()
            .await?;

        Ok(res)
    }

    pub async fn request_jwt(&self, token: &irma::SessionToken) -> Result<String, ClientError> {
        let res = self
            .client
            .get(self.create_url(&format!("v2/irma/jwt/{}", token.0)))
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        Ok(res)
    }

    pub async fn request_decryption_key<K>(
        &self,
        timestamp: u64,
        auth: &str,
    ) -> Result<KeyResponse<UserSecretKey<K>>, ClientError>
    where
        K: IBKEM,
        KeyResponse<UserSecretKey<K>>: DeserializeOwned,
    {
        let res = self
            .client
            .get(self.create_url(&format!("v2/irma/key/{timestamp}")))
            .bearer_auth(auth)
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<KeyResponse<UserSecretKey<K>>>()
            .await?;

        Ok(res)
    }

    pub async fn request_signing_key(
        &self,
        auth: &str,
    ) -> Result<KeyResponse<SigningKeyExt>, ClientError> {
        let res = self
            .client
            .get(self.create_url("v2/irma/sign/key"))
            .bearer_auth(auth)
            .headers(HEADERS.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<KeyResponse<SigningKeyExt>>()
            .await?;

        Ok(res)
    }

    pub async fn wait_on_decryption_key(
        &self,
        sp: &irma::SessionData,
        timestamp: u64,
    ) -> Result<KeyResponse<UserSecretKey<CGWKV>>, ClientError> {
        for _ in 0..120 {
            let jwt: String = self.request_jwt(&sp.token).await?;
            let kr = self.request_decryption_key(timestamp, &jwt).await?;

            match kr {
                kr @ KeyResponse::<UserSecretKey<CGWKV>> {
                    status: irma::SessionStatus::Done,
                    ..
                } => return Ok(kr),
                _ => {
                    delay_for(Duration::new(0, 500_000_000)).await;
                }
            };
        }

        Err(ClientError::Timeout)
    }

    pub async fn wait_on_signing_key(
        &self,
        sp: &irma::SessionData,
    ) -> Result<KeyResponse<SigningKeyExt>, ClientError> {
        for _ in 0..120 {
            let jwt: String = self.request_jwt(&sp.token).await?;
            let kr = self.request_signing_key(&jwt).await?;

            match kr {
                kr @ KeyResponse::<SigningKeyExt> {
                    status: irma::SessionStatus::Done,
                    ..
                } => return Ok(kr),
                _ => {
                    delay_for(Duration::new(0, 500_000_000)).await;
                }
            };
        }

        Err(ClientError::Timeout)
    }
}
