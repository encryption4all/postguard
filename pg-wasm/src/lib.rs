#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
//! PostGuard wasm API.

use pg_core::artifacts::{PublicKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use pg_core::client::web::stream::{StreamSealerConfig, StreamUnsealerConfig};
use pg_core::client::web::{SealerMemoryConfig, UnsealerMemoryConfig};
use pg_core::client::{Header, Sealer, Unsealer};
use pg_core::identity::{EncryptionPolicy, HiddenPolicy};
use pg_core::kem::cgw_kv::CGWKV;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_streams::readable::IntoStream;
use wasm_streams::readable::{sys::ReadableStream as RawReadableStream, ReadableStream};
use wasm_streams::writable::{sys::WritableStream as RawWritableStream, WritableStream};

use js_sys::{Array, Uint8Array};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
interface ISealOptions {
  policy: EncryptionPolicy;
  pubSignKey: ISigningKey;
  privSignKey?: ISigningKey;
}

export type EncryptionPolicy = { [recipient: string]: IPolicy };

interface ISigningKey {
  key: string;
  policy: IPolicy;
}

interface IPolicy {
  con: AttributeCon;
  ts: number;
}

export type AttributeCon = { t: string; v: string }[];
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ISealOptions")]
    pub type ISealOptions;
}

/// Seal options.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

/// A StreamUnsealer is used to decrypt and verify data in a streaming manner.
#[derive(Debug)]
#[wasm_bindgen(js_name = StreamUnsealer)]
pub struct StreamUnsealer(Unsealer<IntoStream<'static>, StreamUnsealerConfig>);

/// An Unsealer is used to decrypt and verify data.
#[derive(Debug)]
#[wasm_bindgen(js_name = Unsealer)]
pub struct MemoryUnsealer(Unsealer<Uint8Array, UnsealerMemoryConfig>);

// Helper to retrieve the recipients from a header.
fn get_recipients(header: &Header) -> Result<JsValue, JsValue> {
    let policies: BTreeMap<String, HiddenPolicy> = header
        .recipients
        .iter()
        .map(|(rid, r_info)| (rid.clone(), r_info.policy.clone()))
        .collect();
    let pol = serde_wasm_bindgen::to_value(&policies)?;

    Ok(pol)
}

/// Seals the contents of a `Uint8Array` into a `Uint8Array` using
/// the given master public key and policies.
///
/// # Arguments
///
/// * `mpk`      - Master public key, can be obtained using, e.g. fetch(`{PKGURL}/v2/parameters`).
/// * `options`  - The seal options [`ISealOptions`].
/// * `plain`    - The plaintext `Uint8Array` for data encapsulation.
#[wasm_bindgen(js_name = seal)]
pub async fn js_seal(
    mpk: JsValue,
    options: ISealOptions,
    plain: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let mut rng = rand::thread_rng();

    let mpk: PublicKey<CGWKV> = serde_wasm_bindgen::from_value(mpk)?;

    let SealOptions {
        policy,
        pub_sign_key,
        priv_sign_key,
    } = serde_wasm_bindgen::from_value(options.into())?;

    let mut sealer = Sealer::<_, SealerMemoryConfig>::new(&mpk, &policy, &pub_sign_key, &mut rng)?;

    if let Some(priv_sign_key) = priv_sign_key {
        sealer = sealer.with_priv_signing_key(priv_sign_key);
    }

    let res = sealer.seal(&plain).await?;

    Ok(res)
}

/// Seals the contents of a `ReadableStream` into a `WritableStream` using
/// the given master public key and policies.
///
/// # Arguments
///
/// * `mpk`      - Master public key, can be obtained using, e.g. fetch(`{PKGURL}/v2/parameters`).
/// * `options`  - The seal options [`ISealOptions`].
/// * `readable` - The plaintext `ReadableStream` for data encapsulation. Only chunks of type `Uint8Array` should be enqueued.
/// * `writable` - The `WritableStream` to which the ciphertext is written. Writes chunks of type `Uint8Array`.
///
/// # Errors
///
/// The seal function expects `Uint8Array` chunks and will error otherwise.
#[wasm_bindgen(js_name = sealStream)]
pub async fn js_stream_seal(
    mpk: JsValue,
    options: ISealOptions,
    readable: RawReadableStream,
    writable: RawWritableStream,
) -> Result<(), JsValue> {
    let mut rng = rand::thread_rng();

    let mpk: PublicKey<CGWKV> = serde_wasm_bindgen::from_value(mpk)?;

    let SealOptions {
        policy,
        pub_sign_key,
        priv_sign_key,
    } = serde_wasm_bindgen::from_value(options.into())?;

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

#[wasm_bindgen(js_class = StreamUnsealer)]
impl StreamUnsealer {
    /// Constructs a new `Unsealer` from a Javascript `ReadableStream`.
    ///
    /// The decrypting party should then use [`Unsealer::inspect_header`]
    /// to retrieve a user secret key for using in [`Unsealer::unseal()`].
    ///
    /// Locks the ReadableStream until this Unsealer is dropped.
    pub async fn new(readable: RawReadableStream, vk: JsValue) -> Result<StreamUnsealer, JsValue> {
        let vk: VerifyingKey = serde_wasm_bindgen::from_value(vk)?;

        let read = ReadableStream::from_raw(readable).into_stream();
        let unsealer = Unsealer::<_, StreamUnsealerConfig>::new(read, &vk).await?;

        Ok(StreamUnsealer(unsealer))
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
        get_recipients(&self.0.header)
    }
}

#[wasm_bindgen(js_class = Unsealer)]
impl MemoryUnsealer {
    /// Create new `Unsealer`.
    pub async fn new(input: Uint8Array, vk: JsValue) -> Result<MemoryUnsealer, JsValue> {
        let vk: VerifyingKey = serde_wasm_bindgen::from_value(vk)?;
        let unsealer = Unsealer::<_, UnsealerMemoryConfig>::new(&input, &vk)?;

        Ok(MemoryUnsealer(unsealer))
    }

    /// Unseal the payload.
    pub async fn unseal(self, recipient_id: String, usk: JsValue) -> Result<Array, JsValue> {
        let usk: UserSecretKey<CGWKV> = serde_wasm_bindgen::from_value(usk)?;
        let (output, pol) = self.0.unseal(&recipient_id, &usk).await?;
        let pol_serialized = serde_wasm_bindgen::to_value(&pol)?;

        let arr = Array::new_with_length(2);
        arr.set(0, output.into());
        arr.set(1, pol_serialized);

        Ok(arr)
    }

    /// Inspects the header for hidden policies in the header.
    /// The user should use this to retrieve a `UserSecretKey` via the PKG.
    pub fn inspect_header(&self) -> Result<JsValue, JsValue> {
        get_recipients(&self.0.header)
    }
}
