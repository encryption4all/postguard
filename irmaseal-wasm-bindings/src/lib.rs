use std::collections::BTreeMap;

use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::SS_BYTES;
use irmaseal_core::stream::{web_seal, WebUnsealer};
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

/// Seals the contents of a `ReadableStream` into a `WritableStream` using
/// the given master public key and policies.
///
/// # Arguments
///
/// * `mpk`      - Master public key, can be obtained using, e.g. fetch(`{PKGURL}/v2/parameters`).
/// * `policies` - The policies to use for key encapsulation.
/// * `readable` - The plaintext `ReadableStream` for data encapsulation. Only chunks of type `Uint8Array` should be enqueued.
/// * `writable` - The `WritableStream` to which the ciphertext is written. Writes chunks of type `Uint8Array`.
///
/// # Errors
///
/// The seal function expects `Uint8Array` chunks and will error otherwise.
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
    /// The decrypting party should then use `Unsealer::get_hidden_policies()`
    /// to retrieve a user secret key for using in `unseal()` or `derive_key()`.
    ///
    /// Locks the ReadableStream until this Unsealer is dropped.`
    pub async fn new(readable: RawReadableStream) -> Result<JsUnsealer, JsValue> {
        let read = ReadableStream::from_raw(readable).into_stream();
        let unsealer = WebUnsealer::new(read).await?;

        Ok(Self(unsealer))
    }

    /// Decrypts the remaining data in the `ReadableStream` (the payload)
    /// into a `WritableStream`.
    ///
    /// # Arguments
    ///
    /// * `recipient_id` - The recipient identifier used for unsealing.
    /// * `usk`          - The User Secret Key associated with the policy of this recipient.
    /// * `writable`     - A `WritableStream` to which the plaintext chunks will be written.
    ///
    /// # Errors
    ///
    /// An error occurs when the ciphertext data is not of type `Uint8Array`.
    /// A WebCrypto error can also occur when the data is not succesfully authenticated.
    pub async fn unseal(
        mut self,
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
    /// The user should use this to retrieve a `UserSecretKey`.
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

    /// Returns the 16-byte initialization vector used for symmetric encryption.
    pub fn get_iv(&self) -> Uint8Array {
        let iv = Uint8Array::new_with_length(self.0.meta.iv.len() as u32);
        iv.copy_from(&self.0.meta.iv);
        iv
    }

    /// Returns the 32-byte shared secret derived from the unsealer and the usk/mpk.
    pub fn derive_key(&self, id: &str, usk: &JsValue) -> Uint8Array {
        let usk: UserSecretKey<CGWKV> = usk.into_serde().unwrap();
        let ss = self
            .0
            .meta
            .policies
            .get(id)
            .unwrap()
            .derive_keys(&usk)
            .unwrap();

        let ss_js = Uint8Array::new_with_length(SS_BYTES as u32);
        ss_js.copy_from(&ss.0);

        ss_js
    }
}
