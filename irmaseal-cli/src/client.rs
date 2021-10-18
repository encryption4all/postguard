use ibe::kem::{Scheme, IBKEM};
use irmaseal_core::{api::*, PublicKey};
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// TODO: Maybe move this to core?
fn version<K: IBKEM>() -> &'static str {
    match K::SCHEME {
        Scheme::KV1 => "v1",
        Scheme::CGWFO => "v2",
    }
}

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
        Url::parse(&self.baseurl).unwrap().join(u).unwrap()
    }

    pub async fn parameters<K>(&self) -> Result<Parameters<K>, ClientError>
    where
        K: IBKEM,
        PublicKey<K>: DeserializeOwned,
    {
        self.client
            .get(self.create_url(&format!("{}/parameters", version::<K>())))
            .send()
            .await?
            .error_for_status()?
            .json::<Parameters<K>>()
            .await
    }

    pub async fn request(&self, kr: &KeyRequest) -> Result<OwnedKeyChallenge, ClientError> {
        self.client
            .post(self.create_url("v2/request"))
            .json(kr)
            .send()
            .await?
            .error_for_status()?
            .json::<OwnedKeyChallenge>()
            .await
    }

    pub async fn result<K>(
        &self,
        token: &str,
        timestamp: u64,
    ) -> Result<KeyResponse<K>, ClientError>
    where
        K: IBKEM,
        KeyResponse<K>: DeserializeOwned,
    {
        self.client
            .get(
                self.create_url(&format!("{}/request/", version::<K>()))
                    .join(&format!("{}/{}", token, timestamp))
                    .unwrap(),
            )
            .send()
            .await?
            .error_for_status()?
            .json::<KeyResponse<K>>()
            .await
    }
}
