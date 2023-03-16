#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
//! PostGuard wasm API.

use std::collections::BTreeMap;

use pg_core::artifacts::{PublicKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use pg_core::client::web::stream::{StreamSealerConfig, StreamUnsealerConfig};
use pg_core::client::{Sealer, Unsealer};
use pg_core::identity::{EncryptionPolicy, HiddenPolicy};
use pg_core::kem::cgw_kv::CGWKV;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_streams::readable::IntoStream;
use wasm_streams::readable::{sys::ReadableStream as RawReadableStream, ReadableStream};
use wasm_streams::writable::{sys::WritableStream as RawWritableStream, WritableStream};

use serde::{Deserialize, Serialize};

/// An Unsealer is used to decrypt and verify data.
#[derive(Debug)]
#[wasm_bindgen(js_name = Unsealer)]
pub struct JsUnsealer(Unsealer<IntoStream<'static>, StreamUnsealerConfig>);

/// Seal options.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealOptions {
    /// The encryption policy.
    pub policy: EncryptionPolicy,

    /// The public signing key plus identity.
    pub pub_sign_key: SigningKeyExt,

    /// The private signing key plus identity.
    ///
    /// Only recipients specified by the `EncryptionPolicy` can see this.
    pub priv_sign_key: Option<SigningKeyExt>,
}

/// Seals the contents of a `ReadableStream` into a `WritableStream` using
/// the given master public key and policies.
///
/// # Arguments
///
/// * `mpk`      - Master public key, can be obtained using, e.g. fetch(`{PKGURL}/v2/parameters`).
/// * `options`  - The seal options [`SealOptions`].
/// * `readable` - The plaintext `ReadableStream` for data encapsulation. Only chunks of type `Uint8Array` should be enqueued.
/// * `writable` - The `WritableStream` to which the ciphertext is written. Writes chunks of type `Uint8Array`.
///
/// # Errors
///
/// The seal function expects `Uint8Array` chunks and will error otherwise.
#[wasm_bindgen(js_name = seal)]
pub async fn js_seal(
    mpk: JsValue,
    options: JsValue,
    readable: RawReadableStream,
    writable: RawWritableStream,
) -> Result<(), JsValue> {
    let mut rng = rand::thread_rng();

    let mpk: PublicKey<CGWKV> = serde_wasm_bindgen::from_value(mpk)?;

    let SealOptions {
        policy,
        pub_sign_key,
        priv_sign_key,
    } = serde_wasm_bindgen::from_value(options)?;

    let read = ReadableStream::from_raw(readable);
    let mut stream = read.into_stream();
    let mut sink = WritableStream::from_raw(writable).into_sink();

    let mut sealer = Sealer::<_, StreamSealerConfig>::new(&mpk, &policy, &pub_sign_key, &mut rng)?;

    if let Some(priv_sign_key) = priv_sign_key {
        sealer = sealer.with_priv_signing_key(priv_sign_key);
    }

    sealer.seal(&mut stream, &mut sink).await?;

    Ok(())
}

#[wasm_bindgen(js_class = Unsealer)]
impl JsUnsealer {
    /// Constructs a new `Unsealer` from a Javascript `ReadableStream`.
    ///
    /// The decrypting party should then use [`Unsealer::inspect_header]`
    /// to retrieve a user secret key for using in [`Unsealer::unseal()`].
    ///
    /// Locks the ReadableStream until this Unsealer is dropped.`
    pub async fn new(readable: RawReadableStream, vk: JsValue) -> Result<JsUnsealer, JsValue> {
        let vk: VerifyingKey = serde_wasm_bindgen::from_value(vk)?;
        let read = ReadableStream::from_raw(readable).into_stream();
        let unsealer = Unsealer::<_, StreamUnsealerConfig>::new(read, &vk).await?;

        Ok(Self(unsealer))
    }

    /// Decrypts the payload from the `ReadableStream` into a `WritableStream`.
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
    ) -> Result<JsValue, JsValue> {
        let usk: UserSecretKey<CGWKV> = serde_wasm_bindgen::from_value(usk)?;

        let mut write = WritableStream::from_raw(writable).into_sink();
        let pol = self.0.unseal(&recipient_id, &usk, &mut write).await?;
        let out = serde_wasm_bindgen::to_value(&pol)?;

        Ok(out)
    }

    /// Inspects the header for hidden policies in the header.
    ///
    /// The user should use this to retrieve a `UserSecretKey` via the PKG.
    pub fn inspect_header(&self) -> Result<JsValue, JsValue> {
        let policies: BTreeMap<String, HiddenPolicy> = self
            .0
            .header
            .recipients
            .iter()
            .map(|(rid, r_info)| (rid.clone(), r_info.policy.clone()))
            .collect();

        let pol = serde_wasm_bindgen::to_value(&policies)?;

        Ok(pol)
    }
}
