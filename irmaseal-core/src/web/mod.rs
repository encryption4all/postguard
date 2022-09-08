//! Implementations backed by [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

#[cfg(all(not(target_arch = "wasm32-unknown-unknown"), not(docsrs)))]
compile_error!("feature \"web\" can only be used for wasm targets");

mod aesgcm;

#[cfg(feature = "web_stream")]
pub mod stream;

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::consts::*;
use crate::header::{Algorithm, Header, Mode};
use crate::identity::Policy;
use crate::web::aesgcm::encrypt;
use crate::web::aesgcm::{decrypt, get_key};
use crate::Error;
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Error as JsError;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use wasm_bindgen::JsValue;

#[doc(inline)]
pub use crate::SealedPacket;

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        JsError::new(err.into()).into()
    }
}

impl SealedPacket<Uint8Array> {
    /// Seals the contents of a `Uint8Array` into a [`SealedPacket`].
    /// See [`SealedPacket`] for serialization methods.
    pub async fn new<R: RngCore + CryptoRng>(
        pk: &PublicKey<CGWKV>,
        policies: &BTreeMap<String, Policy>,
        rng: &mut R,
        input: impl AsRef<Uint8Array>,
    ) -> Result<Self, JsValue> {
        let (header, ss) = Header::new(pk, policies, rng)?;
        let header = header.with_mode(Mode::InMemory {
            size: input.as_ref().length(),
        });

        let iv = match header {
            Header {
                algo: Algorithm::Aes128Gcm(iv),
                ..
            } => iv,
            _ => return Err(Error::AlgorithmNotSupported(header.algo).into()),
        };

        let key = get_key(&ss.0[..KEY_SIZE]).await?;
        let ciphertext =
            encrypt(&key, &iv.0, &Uint8Array::new_with_length(0), input.as_ref()).await?;

        Ok(SealedPacket {
            version: VERSION_V2,
            header,
            ciphertext,
        })
    }

    // to_json
    // to_bin
    // from_json
    // from_bin

    /// Unseals a [`SealedPacket`] into an [`Uint8Array`].
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

        let ss = rec_info.derive_keys(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let iv = match self.header.algo {
            Algorithm::Aes128Gcm(iv) => iv,
            _ => return Err(Error::AlgorithmNotSupported(self.header.algo).into()),
        };

        decrypt(
            &key,
            &iv.0[..],
            &Uint8Array::new_with_length(0),
            &self.payload,
        )
        .await
    }
}
