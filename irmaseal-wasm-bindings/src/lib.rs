use std::collections::BTreeMap;

use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::stream::{web_seal, WebUnsealer};
use irmaseal_core::util::KeySet;
use irmaseal_core::{Error as SealError, HiddenPolicy};
use irmaseal_core::{Policy, PublicKey, UserSecretKey};

use wasm_bindgen::JsValue;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_streams::readable::IntoAsyncRead;
use wasm_streams::readable::{sys::ReadableStream as RawReadableStream, ReadableStream};
use wasm_streams::writable::{sys::WritableStream as RawWritableStream, WritableStream};

use futures::io::AsyncWriteExt;
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, Future};
use js_sys::{Error as JsError, Uint8Array};

extern crate console_error_panic_hook;

pub enum Error {
    Seal(irmaseal_core::Error),
}

// Convert any error to a Javascript error.
impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        match err {
            Error::Seal(e) => match e {
                SealError::NotIRMASEAL => JsError::new("Not IRMASEAL"),
                SealError::IncorrectVersion => JsError::new("Incorrect version"),
                SealError::ConstraintViolation => JsError::new("Constraint violation"),
                SealError::FormatViolation => JsError::new("Format violation"),
                SealError::KeyError => JsError::new("Wrong symmetric key size"),
                SealError::IncorrectTag => JsError::new("Incorrect tag"),
                SealError::StdIO(x) => JsError::new(&format!("IO error: {x}")),
                SealError::FuturesIO(x) => JsError::new(&format!("IO error: {x}")),
                SealError::Kem(_) => JsError::new("KEM failure"),
            },
        }
        .into()
    }
}

#[wasm_bindgen(js_name = Unsealer)]
pub struct JsUnsealer(WebUnsealer<IntoAsyncRead<'static>>);

#[wasm_bindgen(js_name = KeySet)]
pub struct WrappedKeyset(KeySet);

/// Seals the contents of a `ReadableStream` into a `WritableStream`.
#[wasm_bindgen(js_name = seal)]
pub async fn js_seal(
    mpk: JsValue,
    policies: JsValue,
    readable: RawReadableStream,
    writable: RawWritableStream,
) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    let mut rng = rand::thread_rng();
    let pk: PublicKey<CGWKV> = mpk.into_serde().unwrap();
    let pols: BTreeMap<String, Policy> = policies.into_serde().unwrap();

    let mut read = ReadableStream::from_raw(readable);
    let mut stream = read.into_stream().map_ok(|x| x.dyn_into());
    let mut sink = WritableStream::from_raw(writable)

    web_seal(&pk, &pols, &mut rng, &mut stream, &mut sink)
        .await
        .map_err(Error::Seal)?;

    Ok(())
}

#[wasm_bindgen(js_class = Unsealer)]
impl JsUnsealer {
    /// Constructs a new `Unsealer` from a Javascript `ReadableStream`.
    /// The stream forwards up until the payload.
    /// The decrypting party should then use the metadata to retrieve a
    /// user secret key for using in `unseal()` or `get_keys()`.
    ///
    /// Locks the ReadableStream until this Unsealer is dropped.
    #[wasm_bindgen(constructor)]
    pub async fn new(readable: RawReadableStream) -> Result<JsUnsealer, JsValue> {
        let read = ReadableStream::from_raw(readable).into_async_read();

        let unsealer = WebUnsealer::new(read).await.map_err(Error::Seal)?;

        Ok(Self(unsealer))
    }

    /// Decrypts the remaining data in the `ReadableStream` (the payload)
    /// into a `WritableStream`.
    pub async fn unseal(
        mut self,
        recipient_id: String,
        usk: JsValue,
        writable: RawWritableStream,
    ) -> Result<(), JsValue> {
        console_error_panic_hook::set_once();

        let usk: UserSecretKey<CGWKV> = usk.into_serde().unwrap();
        let mut write = WritableStream::from_raw(writable).into_async_write();

        self.0
            .unseal(&recipient_id, &usk, &mut write)
            .await
            .map_err(Error::Seal)?;

        write.close().await.unwrap();

        Ok(())
    }

    /// Returns all hidden policies in the metadata.
    /// The user can use this to retrieve a `UserSecretKey`.
    pub fn get_hidden_policies(&self) -> JsValue {
        let policies: BTreeMap<String, HiddenPolicy> = self
            .0
            .meta
            .policies
            .iter()
            .map(|(rid, r_info)| (rid.clone(), r_info.policy.clone()))
            .collect();

        JsValue::from_serde(&policies).unwrap()
    }

    /// Returns the chunk size used during symmetric encryption.
    pub fn get_chunk_size(&self) -> usize {
        self.0.meta.chunk_size
    }

    /// Returns the intitialization vector used for symmetric encryption.
    pub fn get_iv(&self) -> Uint8Array {
        let iv = Uint8Array::new_with_length(self.0.meta.iv.len() as u32);
        iv.copy_from(&self.0.meta.iv);
        iv
    }

    /// Returns the symmetric keys derived from the unsealer and the usk/mpk.
    pub fn derive_keys(&self, id: &str, usk: &JsValue) -> WrappedKeyset {
        let usk: UserSecretKey<CGWKV> = usk.into_serde().unwrap();
        let keyset = self
            .0
            .meta
            .policies
            .get(id)
            .unwrap()
            .derive_keys(&usk)
            .unwrap();

        WrappedKeyset(keyset)
    }
}

#[wasm_bindgen(js_class = KeySet)]
impl WrappedKeyset {
    #[wasm_bindgen(getter)]
    pub fn aes_key(&self) -> Uint8Array {
        let key = Uint8Array::new_with_length(self.0.aes_key.len() as u32);
        key.copy_from(&self.0.aes_key);
        key
    }

    #[wasm_bindgen(getter)]
    pub fn mac_key(&self) -> Uint8Array {
        let key = Uint8Array::new_with_length(self.0.mac_key.len() as u32);
        key.copy_from(&self.0.mac_key);
        key
    }
}
