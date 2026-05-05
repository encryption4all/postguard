use pg_core::api::*;
use pg_core::artifacts::{PublicKey, UserSecretKey, VerifyingKey};
use pg_core::kem::IBKEM;

use pg_core::kem::cgw_kv::CGWKV;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use std::fmt;
use std::time::Duration;
use tokio::time::sleep;
use url::ParseError as UrlParseError;

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
    InvalidUrl { url: String, source: UrlParseError },
    Reqwest(reqwest::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Timeout => write!(f, "timed out waiting for PKG response"),
            ClientError::InvalidUrl { url, source } => {
                write!(f, "invalid PKG URL '{}': {}", url, source)
            }
            ClientError::Reqwest(e) => write!(f, "PKG request failed: {}", e),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Timeout => None,
            ClientError::InvalidUrl { source, .. } => Some(source),
            ClientError::Reqwest(e) => Some(e),
        }
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Reqwest(e)
    }
}

impl<'a> Client<'a> {
    pub fn new(baseurl: &'a str) -> Result<Client<'a>, ClientError> {
        // Validate the base URL up front so the user gets a clear error
        // instead of a panic on the first request.
        Url::parse(baseurl).map_err(|source| ClientError::InvalidUrl {
            url: baseurl.to_string(),
            source,
        })?;
        let client = ClientBuilder::new().build()?;
        Ok(Client { baseurl, client })
    }

    fn create_url(&self, u: &str) -> Result<Url, ClientError> {
        Url::parse(self.baseurl)
            .and_then(|base| base.join(u))
            .map_err(|source| ClientError::InvalidUrl {
                url: format!("{}{}", self.baseurl, u),
                source,
            })
    }

    pub async fn parameters<K>(&self) -> Result<Parameters<PublicKey<K>>, ClientError>
    where
        K: IBKEM,
        PublicKey<K>: DeserializeOwned,
    {
        let res = self
            .client
            .get(self.create_url("v2/parameters")?)
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
            .get(self.create_url("v2/sign/parameters")?)
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
            .post(self.create_url("v2/irma/start")?)
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
            .get(self.create_url(&format!("v2/irma/jwt/{}", token.0))?)
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
            .get(self.create_url(&format!("v2/irma/key/{timestamp}"))?)
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
        body: &SigningKeyRequest,
    ) -> Result<SigningKeyResponse, ClientError> {
        let res = self
            .client
            .post(self.create_url("v2/irma/sign/key")?)
            .bearer_auth(auth)
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json::<SigningKeyResponse>()
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
                    sleep(Duration::new(0, 500_000_000)).await;
                }
            };
        }

        Err(ClientError::Timeout)
    }

    pub async fn wait_on_signing_keys(
        &self,
        sp: &irma::SessionData,
        body: &SigningKeyRequest,
    ) -> Result<SigningKeyResponse, ClientError> {
        for _ in 0..120 {
            let jwt: String = self.request_jwt(&sp.token).await?;
            let kr = self.request_signing_key(&jwt, body).await?;

            match kr {
                kr @ SigningKeyResponse {
                    status: irma::SessionStatus::Done,
                    ..
                } => return Ok(kr),
                _ => {
                    sleep(Duration::new(0, 500_000_000)).await;
                }
            };
        }

        Err(ClientError::Timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_baseurl() {
        let err = match Client::new("not a url") {
            Ok(_) => panic!("expected error for malformed URL"),
            Err(e) => e,
        };
        match err {
            ClientError::InvalidUrl { url, .. } => assert_eq!(url, "not a url"),
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_baseurl_and_joins_paths() {
        let client = Client::new("https://example.invalid").expect("valid url");
        let url = client.create_url("v2/parameters").expect("joined url");
        assert_eq!(url.as_str(), "https://example.invalid/v2/parameters");
    }

    #[test]
    fn create_url_joins_with_trailing_slash() {
        let client = Client::new("https://example.invalid/").expect("valid url");
        let url = client.create_url("v2/whatever/123").expect("joined");
        assert!(url.as_str().ends_with("/v2/whatever/123"));
    }
}
