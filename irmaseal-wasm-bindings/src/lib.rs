use std::collections::BTreeMap;

use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::stream::{web_seal, WebUnsealer};
use irmaseal_core::util::KeySet;
use irmaseal_core::{HiddenPolicy, Policy, PublicKey, UserSecretKey};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_streams::readable::IntoStream;
use wasm_streams::readable::{sys::ReadableStream as RawReadableStream, ReadableStream};
use wasm_streams::writable::{sys::WritableStream as RawWritableStream, WritableStream};

extern crate console_error_panic_hook;

#[wasm_bindgen(js_name = Unsealer)]
pub struct JsUnsealer(WebUnsealer<IntoStream<'static>>);

#[wasm_bindgen(js_name = KeySet)]
pub struct WrappedKeyset(KeySet);

/// Seals the contents of a `ReadableStream` into a `WritableStream`.
///
/// # Arguments
///
/// * `mpk` - Master public key, can be obtained using, e.g. fetch(`{PKGURL}/v2/parameters`).
/// * `policies` - The policies to use for key encapsulation.
/// * `readable` - The plaintext `ReadableStream` for data encapsulation.
/// * `writable`-  The `WritableStream` to which the ciphertext is written.
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

    let read = ReadableStream::from_raw(readable);
    let mut stream = read.into_stream();
    let mut sink = WritableStream::from_raw(writable).into_sink();

    web_seal(&pk, &pols, &mut rng, &mut stream, &mut sink).await?;

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
        let read = ReadableStream::from_raw(readable).into_stream();
        let unsealer = WebUnsealer::new(read).await?;

        Ok(Self(unsealer))
    }

    /// Decrypts the remaining data in the `ReadableStream` (the payload)
    /// into a `WritableStream`.
    pub async fn unseal(
        self,
        recipient_id: String,
        usk: JsValue,
        writable: RawWritableStream,
    ) -> Result<(), JsValue> {
        console_error_panic_hook::set_once();

        let usk: UserSecretKey<CGWKV> = usk.into_serde().unwrap();
        let mut write = WritableStream::from_raw(writable).into_sink();

        self.0.unseal(&recipient_id, &usk, &mut write).await?;

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
