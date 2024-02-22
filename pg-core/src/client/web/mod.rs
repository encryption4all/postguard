//! Implementation for the web, backed by [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
//!
//! This module utilizes the symmetric primitives provided by [Web
//! Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The streaming
//! interface, enabled using the feature `"stream"` enables an interface to encrypt data from a
//! [`Stream<Item = Result<Uint8Array, JsValue>>`][`futures::stream::Stream`] into a
//! [`Sink<Uint8Array, Error = JsValue>`][`futures::sink::Sink`]. These can easily interact with
//! [Web Streams](https://developer.mozilla.org/en-US/docs/Web/API/Streams_API) using the
//! [wasm-streams](https://docs.rs/wasm-streams/latest/wasm_streams/index.html) crate.
//!
//! This module is only available on the `target = "wasm32-unknown-unknown"` and the output
//! _should_ be used in browser environments. This also greatly reduces the bundle size.
//!
//! This module can largely be simplified when [the AEAD crate](https://docs.rs/aead/latest/aead/index.html) will support async, see
//! [the relevant issue](https://github.com/RustCrypto/traits/issues/304).
//!

#[cfg(not(any(target_arch = "wasm32", docsrs)))]
compile_error!("\"web\" feature should only be enabled on wasm32 targets");

mod aesgcm;

#[cfg(feature = "stream")]
pub mod stream;

use super::web::aesgcm::encrypt;
use super::web::aesgcm::{decrypt, get_key};

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::EncryptionPolicy;

use ibe::kem::cgw_kv::CGWKV;
use ibs::gg::Signer;

use js_sys::Error as JsError;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use wasm_bindgen::JsValue;

use alloc::string::ToString;
use alloc::vec::Vec;

/// In-memory configuration for a [`Sealer`].
#[derive(Debug)]
pub struct SealerMemoryConfig {
    key: [u8; KEY_SIZE],
    nonce: [u8; IV_SIZE],
}

/// In-memory configuration for an [`Unsealer`].
#[derive(Debug)]
pub struct UnsealerMemoryConfig {
    message_len: usize,
}

impl SealerConfig for SealerMemoryConfig {}
impl super::sealed::SealerConfig for SealerMemoryConfig {}

impl UnsealerConfig for UnsealerMemoryConfig {}
impl super::sealed::UnsealerConfig for UnsealerMemoryConfig {}

#[derive(Debug, Serialize, Deserialize)]
struct MessageAndSignature {
    message: Vec<u8>,
    sig: Option<SignatureExt>,
}

impl<'r, R: RngCore + CryptoRng> Sealer<'r, R, SealerMemoryConfig> {
    /// Create a new [`Sealer`].
    pub fn new(
        mpk: &PublicKey<CGWKV>,
        policies: &EncryptionPolicy,
        pub_sign_key: &SigningKeyExt,
        rng: &'r mut R,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; IV_SIZE];
        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..IV_SIZE]);

        Ok(Self {
            rng,
            header,
            pub_sign_key: Some(pub_sign_key.clone()),
            priv_sign_key: None,
            config: SealerMemoryConfig { key, nonce },
        })
    }

    /// Seals the entire payload.
    pub async fn seal(mut self, message: &Uint8Array) -> Result<Uint8Array, Error> {
        let mut out = Vec::with_capacity(message.byte_length() as usize + 1024);

        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&VERSION_V3.to_be_bytes());
        self.header = self.header.with_mode(Mode::InMemory {
            size: message.byte_length(),
        });

        let header_buf = bincode::serialize(&self.header)?;
        out.extend_from_slice(&(header_buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_buf);

        let mut input: Vec<u8> = [].to_vec();

        if self.pub_sign_key.is_some() {
            let pub_sign_key = self.pub_sign_key.unwrap();
            let signer = Signer::new().chain(header_buf);
            let h_sig = signer.clone().sign(&pub_sign_key.key.0, self.rng);

            let h_sig_ext = SignatureExt {
                sig: h_sig,
                pol: pub_sign_key.policy.clone(),
            };

            let h_sig_ext_bytes = bincode::serialize(&h_sig_ext)?;
            out.extend_from_slice(&(h_sig_ext_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&h_sig_ext_bytes);

            let m: Vec<u8> = message.to_vec();
            let m_sig_key = self.priv_sign_key.unwrap_or(pub_sign_key);
            let m_sig = signer.chain(&m).sign(&m_sig_key.key.0, self.rng);

            input = bincode::serialize(&MessageAndSignature {
                message: m,
                sig: Some(SignatureExt {
                    sig: m_sig,
                    pol: m_sig_key.policy.clone(),
                }),
            })?;
        } else {
            input = bincode::serialize(&MessageAndSignature {
                message: message.to_vec(),
                sig: None,
            })?;
        }

        let key = get_key(&self.config.key).await?;
        let ciphertext = encrypt(
            &key,
            &self.config.nonce,
            &Uint8Array::new_with_length(0),
            &Uint8Array::from(input.as_slice()),
        )
        .await?;

        out.extend_from_slice(&ciphertext.to_vec());

        Ok(Uint8Array::from(out.as_slice()))
    }
}

impl Unsealer<Uint8Array, UnsealerMemoryConfig> {
    /// Create a new [`Unsealer`].
    pub fn new(input: &Uint8Array, vk: &VerifyingKey) -> Result<Self, Error> {
        let b = input.to_vec();
        let (preamble_bytes, b) = b.split_at(PREAMBLE_SIZE);
        let (version, header_len) = preamble_checked(preamble_bytes)?;

        let (header_bytes, b) = b.split_at(header_len);

        let (h_sig_len_bytes, b) = b.split_at(SIG_SIZE_SIZE);
        let h_sig_len = u32::from_be_bytes(h_sig_len_bytes.try_into()?);
        let (h_sig_bytes, ct) = b.split_at(h_sig_len as usize);

        let (verifier, pub_id) = if h_sig_len != 0 {
            let h_sig_ext: SignatureExt = bincode::deserialize(h_sig_bytes)?;
            let id = h_sig_ext.pol.derive_ibs()?;
            let verifier = Verifier::default().chain(&header_bytes);

            if !verifier.clone().verify(&vk.0, &h_sig_ext.sig, &id) {
                return Err(Error::IncorrectSignature.into());
            }

            (Some(verifier), Some(h_sig_ext.pol))
        } else {
            (None, None)
        };

        let header: Header = bincode::deserialize(header_bytes)?;
        let message_len = match header.mode {
            Mode::InMemory { size } => size as usize,
            _ => return Err(Error::ModeNotSupported(header.mode).into()),
        };

        Ok(Self {
            version,
            header,
            pub_id: pub_id,
            r: Uint8Array::from(ct),
            verifier,
            vk: vk.clone(),
            config: UnsealerMemoryConfig { message_len },
        })
    }

    /// Unseals the payload.
    pub async fn unseal(
        self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
    ) -> Result<(Uint8Array, Option<VerificationResult>), Error> {
        let rec_info = self
            .header
            .recipients
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let Algorithm::Aes128Gcm(iv) = self.header.algo;

        let plain = decrypt(&key, &iv.0, &Uint8Array::new_with_length(0), &self.r)
            .await?
            .to_vec();

        let msg: MessageAndSignature = bincode::deserialize(&plain).map_err(Into::<Error>::into)?;

        let verification_result = if msg.sig.is_some() {
            let sig = msg.sig.unwrap();
            let id = sig.pol.derive_ibs()?;
            let verified = self
                .verifier
                .unwrap()
                .chain(&msg.message)
                .verify(&self.vk.0, &sig.sig, &id);

            if !verified {
                return Err(Error::IncorrectSignature.into());
            }

            if let Some(pub_id) = self.pub_id {
                let private = if pub_id == sig.pol {
                    None
                } else {
                    Some(sig.pol)
                };

                Some(VerificationResult {
                    public: Some(pub_id),
                    private,
                })
            } else {
                None
            }
        } else {
            None
        };
        debug_assert_eq!(self.config.message_len, msg.message.len());

        let res = Uint8Array::from(msg.message.as_slice());

        Ok((res, verification_result))
    }
}

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        JsError::new(&err.to_string()).into()
    }
}

impl From<JsValue> for Error {
    fn from(e: JsValue) -> Self {
        Error::JavaScript(e)
    }
}
