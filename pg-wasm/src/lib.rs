use std::collections::BTreeMap;

use pg_core::artifacts::{PublicKey, UserSecretKey};
use pg_core::identity::{HiddenRecipientPolicy, Policy};
use pg_core::kem::cgw_kv::CGWKV;
use pg_core::kem::SS_BYTES;
use pg_core::web::stream::{StreamSealerConfig, StreamUnsealerConfig};
use pg_core::{Sealer, Unsealer};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_streams::readable::IntoStream;
use wasm_streams::readable::{sys::ReadableStream as RawReadableStream, ReadableStream};
use wasm_streams::writable::{sys::WritableStream as RawWritableStream, WritableStream};

#[wasm_bindgen(js_name = Unsealer)]
pub struct JsUnsealer(Unsealer<IntoStream<'static>, StreamUnsealerConfig>);

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
    let mut rng = rand::thread_rng();
    let mpk: PublicKey<CGWKV> = serde_wasm_bindgen::from_value(mpk)?;
    let pol: Policy = serde_wasm_bindgen::from_value(policies)?;

    let read = ReadableStream::from_raw(readable);
    let mut stream = read.into_stream();
    let mut sink = WritableStream::from_raw(writable).into_sink();

    Sealer::<StreamSealerConfig>::new(&mpk, &pol, &mut rng)?
        .seal(&mut stream, &mut sink)
        .await?;

    Ok(())
}

#[wasm_bindgen(js_class = Unsealer)]
impl JsUnsealer {
    /// Constructs a new `Unsealer` from a Javascript `ReadableStream`.
    /// The stream forwards up until the payload.
    /// The decrypting party should then use `Unsealer::hidden_policies()`
    /// to retrieve a user secret key for using in `unseal()` or `derive_key()`.
    ///
    /// Locks the ReadableStream until this Unsealer is dropped.`
    pub async fn new(readable: RawReadableStream) -> Result<JsUnsealer, JsValue> {
        let read = ReadableStream::from_raw(readable).into_stream();
        let unsealer = Unsealer::<_, StreamUnsealerConfig>::new(read).await?;

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
        let usk: UserSecretKey<CGWKV> = serde_wasm_bindgen::from_value(usk)?;
        let mut write = WritableStream::from_raw(writable).into_sink();

        self.0.unseal(&recipient_id, &usk, &mut write).await?;

        Ok(())
    }

    /// Returns all hidden policies in the header.
    /// The user should use this to retrieve a `UserSecretKey`.
    pub fn hidden_policies(&self) -> Result<JsValue, JsValue> {
        let policies: BTreeMap<String, HiddenRecipientPolicy> = self
            .0
            .header
            .policies
            .iter()
            .map(|(rid, r_info)| (rid.clone(), r_info.policy.clone()))
            .collect();

        let pol = serde_wasm_bindgen::to_value(&policies)?;

        Ok(pol)
    }

    /// Returns the algorithm used during symmetric encryption.
    pub fn algo(&self) -> Result<JsValue, JsValue> {
        let algo = serde_wasm_bindgen::to_value(&self.0.header.algo)?;

        Ok(algo)
    }

    /// Returns the mode used during symmetric encryption.
    pub fn mode(&self) -> Result<JsValue, JsValue> {
        let mode = serde_wasm_bindgen::to_value(&self.0.header.mode)?;

        Ok(mode)
    }

    /// Returns the 32-byte shared secret derived from the unsealer and the usk/mpk.
    pub fn derive_key(&self, id: &str, usk: JsValue) -> Result<Uint8Array, JsValue> {
        let usk: UserSecretKey<CGWKV> = serde_wasm_bindgen::from_value(usk)?;
        let ss = self
            .0
            .header
            .policies
            .get(id)
            .ok_or_else(|| JsValue::from(JsError::new(&format!("unknown identifier: {}", id))))?
            .decaps(&usk)?;

        let ss_js = Uint8Array::new_with_length(SS_BYTES as u32);
        ss_js.copy_from(&ss.0);

        Ok(ss_js)
    }
}
