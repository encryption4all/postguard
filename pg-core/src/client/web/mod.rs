//! Implementation for the web, backed by [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

// FIXME
//#[cfg(all(not(target_arch = "wasm32-unknown-unknown"), not(docsrs)))]
//compile_error!("feature \"web\" can only be used for wasm targets");

mod aesgcm;

#[cfg(feature = "web_stream")]
pub mod stream;

use super::web::aesgcm::encrypt;
use super::web::aesgcm::{decrypt, get_key};

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::Policy;

use ibe::kem::cgw_kv::CGWKV;
use js_sys::Error as JsError;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use wasm_bindgen::JsValue;

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        JsError::new(&err.to_string()).into()
    }
}

/// In-memory configuration for a [`Sealer`].
#[derive(Debug)]
pub struct SealerMemoryConfig {
    key: [u8; KEY_SIZE],
    nonce: [u8; IV_SIZE],
}

/// In-memory configuration for an [`Unsealer`].
#[derive(Debug)]
pub struct UnsealerMemoryConfig {}

impl SealerConfig for SealerMemoryConfig {}
impl super::sealed::SealerConfig for SealerMemoryConfig {}

impl UnsealerConfig for UnsealerMemoryConfig {}
impl super::sealed::UnsealerConfig for UnsealerMemoryConfig {}

impl Sealer<SealerMemoryConfig> {
    /// Create a new [`Sealer`].
    pub fn new<R: RngCore + CryptoRng>(
        mpk: &PublicKey<CGWKV>,
        policies: &Policy,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..12]);

        Ok(Self {
            header,
            config: SealerMemoryConfig { key, nonce },
        })
    }

    /// Seals the payload.
    ///
    /// See [`SealedPacket`] for serialization methods.
    pub async fn seal(mut self, input: &Uint8Array) -> Result<SealedPacket, JsValue> {
        self.header = self.header.with_mode(Mode::InMemory {
            size: input.byte_length(),
        });

        let key = get_key(&self.config.key).await?;
        let ciphertext = encrypt(
            &key,
            &self.config.nonce,
            &Uint8Array::new_with_length(0),
            input,
        )
        .await?
        .to_vec();

        Ok(SealedPacket {
            version: VERSION_V2,
            header: self.header,
            ciphertext,
        })
    }
}

impl Unsealer<SealedPacket, UnsealerMemoryConfig> {
    /// Blabla
    pub async fn unseal(
        self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
    ) -> Result<Uint8Array, JsValue> {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let Algorithm::Aes128Gcm(iv) = self.header.algo;

        let ct = Uint8Array::new_with_length(
            self.r
                .ciphertext
                .len()
                .try_into()
                .map_err(|_| Error::ConstraintViolation)?,
        );
        ct.copy_from(&self.r.ciphertext);

        decrypt(&key, &iv.0[..], &Uint8Array::new_with_length(0), &ct).await
    }
}
