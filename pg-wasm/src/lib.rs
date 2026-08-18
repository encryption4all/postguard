#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
//! PostGuard wasm API.

use pg_core::artifacts::{PublicKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use pg_core::challenge::{sign_challenge, verify_challenge};
use pg_core::client::web::stream::{StreamSealerConfig, StreamUnsealerConfig};
use pg_core::client::web::{SealerMemoryConfig, UnsealerMemoryConfig};
use pg_core::client::{Header, Sealer, Unsealer};
use pg_core::identity::{Attribute, EncryptionPolicy, HiddenPolicy, Policy};
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
  skipEncryption?: boolean;
  policy?: EncryptionPolicy;
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

export type AttributeCon = { t: string; v?: string }[];
"#;

#[wasm_bindgen]
extern "C" {
    /// Seal options type from TypeScript.
    #[wasm_bindgen(typescript_type = "ISealOptions")]
    pub type ISealOptions;

    /// Signing key type from TypeScript.
    #[wasm_bindgen(typescript_type = "ISigningKey")]
    pub type ISigningKey;

    /// Policy type from TypeScript.
    #[wasm_bindgen(typescript_type = "IPolicy")]
    pub type IPolicy;
}

/// Seal options.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealOptions {
    /// Whether a default enc policy is used to "skip" enc.
    pub skip_encryption: Option<bool>,

    /// The encryption policy.
    pub policy: Option<EncryptionPolicy>,

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

/// Rewrites an attribute value into the canonical form its type expects.
///
/// Sealing applies this automatically, so a policy does not have to be
/// canonicalized before it is passed to [`js_seal`]. Call this to show a user
/// the value that will actually be encrypted to, or to normalize an input field
/// as it is typed.
///
/// The function is total: a value it cannot bring into canonical form — a bare
/// national phone number, which needs a country to resolve — is returned
/// unchanged. Use [`js_is_canonical`] to detect that.
///
/// # Arguments
///
/// * `atype` - The attribute type, e.g. `pbdf.sidn-pbdf.email.email`.
/// * `value` - The attribute value.
#[wasm_bindgen(js_name = canonicalize)]
pub fn js_canonicalize(atype: &str, value: &str) -> String {
    pg_core::identity::canonicalize(atype, value)
}

/// Whether an attribute value is already in the canonical form its type
/// expects.
///
/// Types that carry no canonicalization rule are always canonical. For a mobile
/// number this is stricter than "[`js_canonicalize`] would not change it": the
/// value must also be valid E.164, which is what lets a policy editor reject a
/// bare national number before it produces a container nobody can decrypt.
///
/// # Arguments
///
/// * `atype` - The attribute type, e.g. `pbdf.sidn-pbdf.email.email`.
/// * `value` - The attribute value.
#[wasm_bindgen(js_name = isCanonical)]
pub fn js_is_canonical(atype: &str, value: &str) -> bool {
    pg_core::identity::is_canonical(atype, value)
}

/// Signs a challenge chosen by a verifier, proving possession of a signing key
/// without revealing it.
///
/// The signed message carries a domain separator that this function applies
/// itself, so the result can never double as a signature over a container
/// header. That is the point of the call: a verifier that could pick the whole
/// signed message would be able to have a header signed for a container it
/// wrote.
///
/// # Arguments
///
/// * `key`       - The signing key to prove possession of, as `fetchKey("sign/key", ...)` returns it (see the README).
/// * `context`   - What the proof is for, e.g. an endpoint or an upload id.
/// * `challenge` - The `Uint8Array` the verifier chose.
#[wasm_bindgen(js_name = signChallenge)]
pub fn js_sign_challenge(
    key: ISigningKey,
    context: &str,
    challenge: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let mut rng = rand::thread_rng();

    let key: SigningKeyExt = serde_wasm_bindgen::from_value(key.into())?;
    let sig = sign_challenge(&key, context, &challenge.to_vec(), &mut rng);
    let bytes = pg_core::bincode_compat::serialize(&sig).map_err(pg_core::error::Error::from)?;

    Ok(Uint8Array::from(bytes.as_slice()))
}

/// Verifies a challenge signature against the identity the policy derives to.
///
/// The identity is derived from the policy, which canonicalizes attribute
/// values, so this answers whether the signer holds the key for that identity
/// rather than whether its policy is spelled the same way. Use
/// [`js_canonicalize`] before keying anything on a raw attribute value.
///
/// # Arguments
///
/// * `vk`        - The verifying key, can be obtained using, e.g. fetch(`{PKGURL}/v2/sign/parameters`).
/// * `pol`       - The policy whose identity the signer should hold a key for.
/// * `context`   - The same context the signature was requested under.
/// * `challenge` - The `Uint8Array` this verifier chose.
/// * `sig`       - The signature as returned by [`js_sign_challenge`].
///
/// # Errors
///
/// Errors when `vk` or `pol` cannot be read; those are the verifier's own
/// inputs. A `sig` that is not a well-formed signature is a failed proof, not
/// an error, and returns `false`.
#[wasm_bindgen(js_name = verifyChallenge)]
pub fn js_verify_challenge(
    vk: JsValue,
    pol: IPolicy,
    context: &str,
    challenge: Uint8Array,
    sig: Uint8Array,
) -> Result<bool, JsValue> {
    let vk: VerifyingKey = serde_wasm_bindgen::from_value(vk)?;
    let pol: Policy = serde_wasm_bindgen::from_value(pol.into())?;

    // Decoding stops at the end of the signature, so require the exact length
    // as well: a caller must not be able to hang extra bytes off a valid proof.
    if sig.length() as usize != pg_core::ibs::gg::SIG_BYTES {
        return Ok(false);
    }

    let Ok(sig) = pg_core::bincode_compat::deserialize(&sig.to_vec()) else {
        return Ok(false);
    };

    Ok(verify_challenge(
        &vk,
        &pol,
        context,
        &challenge.to_vec(),
        &sig,
    ))
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
        skip_encryption,
        policy,
        pub_sign_key,
        priv_sign_key,
    } = serde_wasm_bindgen::from_value(options.into())?;

    let skip_encryption = skip_encryption.unwrap_or(false);

    // if skip_encryption is true, then use a default policy such that everyone can decrypt
    let mut sealer = if skip_encryption {
        let policy = EncryptionPolicy::from([(
            String::from("Default"),
            Policy {
                timestamp: 0,
                con: vec![Attribute::new("default", Some("Default"))],
            },
        )]);
        Sealer::<_, SealerMemoryConfig>::new(&mpk, &policy, &pub_sign_key, &mut rng)?
    } else {
        Sealer::<_, SealerMemoryConfig>::new(&mpk, &policy.unwrap(), &pub_sign_key, &mut rng)?
    };

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
        skip_encryption,
        policy,
        pub_sign_key,
        priv_sign_key,
    } = serde_wasm_bindgen::from_value(options.into())?;

    let read = ReadableStream::from_raw(readable);
    let mut stream = read.into_stream();
    let mut sink = WritableStream::from_raw(writable).into_sink();

    let skip_encryption = skip_encryption.unwrap_or(false);

    let mut sealer = if skip_encryption {
        let policy = EncryptionPolicy::from([(
            String::from("Default"),
            Policy {
                timestamp: 0,
                con: vec![Attribute::new("default", Some("Default"))],
            },
        )]);
        Sealer::<_, StreamSealerConfig>::new(&mpk, &policy, &pub_sign_key, &mut rng)?
    } else {
        Sealer::<_, StreamSealerConfig>::new(&mpk, &policy.unwrap(), &pub_sign_key, &mut rng)?
    };

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
    /// A WebCrypto error can also occur when the data is not successfully authenticated.
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

    /// Returns the verified public identity of the sender.
    pub fn public_identity(&self) -> Result<JsValue, JsValue> {
        Ok(serde_wasm_bindgen::to_value(&self.0.pub_id)?)
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

    /// Returns the verified public identity of the sender.
    pub fn public_identity(&self) -> Result<JsValue, JsValue> {
        Ok(serde_wasm_bindgen::to_value(&self.0.pub_id)?)
    }
}
