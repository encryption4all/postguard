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
//! This module is only available on the `target_arch = "wasm32-unknown-unknown"` and the output
//! _should_ be used in browser environments. This also greatly reduces the bundle size.
//!
//! This module can largely be simplified when [the AEAD crate](https://docs.rs/aead/latest/aead/index.html) will support async, see
//! [the relevant issue](https://github.com/RustCrypto/traits/issues/304).
//!
#[cfg(not(any(target_arch = "wasm32-unknown-unknown", docsrs)))]
compile_error!("this module can only be used on wasm targets");

mod aesgcm;

#[cfg(feature = "stream")]
pub mod stream;

use super::web::aesgcm::encrypt;
use super::web::aesgcm::{decrypt, get_key};

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::{EncryptionPolicy, Policy};

use ibe::kem::cgw_kv::CGWKV;
use js_sys::Error as JsError;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use wasm_bindgen::JsValue;

use alloc::vec::Vec;

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
    sig: SignatureExt,
}

impl Sealer<SealerMemoryConfig> {
    /// Create a new [`Sealer`].
    pub fn new<R: RngCore + CryptoRng>(
        mpk: &PublicKey<CGWKV>,
        policies: &EncryptionPolicy,
        pub_sign_key: &SigningKeyExt,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; IV_SIZE];
        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..IV_SIZE]);

        Ok(Self {
            header,
            pub_sign_key: pub_sign_key.clone(),
            priv_sign_key: None,
            config: SealerMemoryConfig { key, nonce },
        })
    }

    /// Seals the entire payload.
    pub async fn seal<R: RngCore + CryptoRng>(
        mut self,
        message: &Uint8Array,
        rng: &mut R,
    ) -> Result<Uint8Array, Error> {
        let mut out = Vec::with_capacity(message.byte_length() + 1024);

        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&VERSION_V3.to_be_bytes());
        self.header = self.header.with_mode(Mode::InMemory {
            size: message
                .byte_length()
                .as_ref()
                .len()
                .try_into()
                .map_err(|_| Error::ConstraintViolation)?,
        });

        let header_buf = self.header.into_bytes()?;
        out.extend_from_slice(
            &u32::try_from(header_buf.len())
                .map_err(|_| Error::ConstraintViolation)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&header_buf);

        let h_signer = Signer::new().chain(header_buf);
        let m_signer = h_signer.clone();
        let h_sig = h_signer.sign(&self.pub_sign_key.key.0, rng);

        let h_sig_ext = SignatureExt {
            sig: h_sig,
            pol: self.pub_sign_key.policy.clone(),
        };

        let h_sig_ext_bytes = bincode::serialize(&h_sig_ext).unwrap();
        out.extend_from_slice(
            &u32::try_from(h_sig_ext_bytes.len())
                .map_err(|_| Error::ConstraintViolation)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&h_sig_ext_bytes);

        let m_sig_key = self.priv_sign_key.unwrap_or(self.pub_sign_key);
        let m_sig = m_signer.chain(&message).sign(&m_sig_key.key.0, rng);

        let enc_input = bincode::serialize(&MessageAndSignature {
            message: message.as_ref().to_vec(),
            sig: SignatureExt {
                sig: m_sig,
                pol: m_sig_key.policy.clone(),
            },
        })
        .unwrap();

        let key = get_key(&self.config.key).await?;
        let ciphertext = encrypt(
            &key,
            &self.config.nonce,
            &Uint8Array::new_with_length(0),
            enc_input,
        )
        .await?;

        out.extend_from_slice(&ciphertext);

        let res = Uint8Array::new_with_length(out.len());
        res.copy_from(&out[..]);

        Ok(res)
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
        let h_sig_len = u32::from_be_bytes(h_sig_len_bytes.try_into().unwrap());
        let (h_sig_bytes, ct) = b.split_at(h_sig_len as usize);

        let h_sig_ext: SignatureExt = bincode::deserialize(h_sig_bytes).unwrap();
        let id = Identity::from(h_sig_ext.pol.derive::<IDENTITY_BYTES>().unwrap());

        let h_verifier = Verifier::default().chain(&header_bytes);
        let m_verifier = h_verifier.clone();

        if !h_verifier.verify(&vk.0, &h_sig_ext.sig, &id) {
            return Err(Error::IncorrectSignature);
        }

        let header = Header::from_bytes(header_bytes)?;
        let message_len = match header.mode {
            Mode::InMemory { size } => size as usize,
            _ => return Err(Error::ModeNotSupported(header.mode)),
        };

        Ok(Self {
            version,
            header,
            r: ct.to_vec(),
            verifier: m_verifier,
            vk: vk.clone(),
            config: UnsealerMemoryConfig { message_len },
        })
    }

    /// Unseals the payload.
    pub async fn unseal(
        self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
    ) -> Result<(Uint8Array, Policy), Error> {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = &ss.0[..KEY_SIZE];

        let Algorithm::Aes128Gcm(iv) = self.header.algo;

        let ct = Uint8Array::new_with_length(
            self.r
                .ciphertext
                .len()
                .try_into()
                .map_err(|_| Error::ConstraintViolation)?,
        );
        ct.copy_from(&self.r.ciphertext);

        let plain = decrypt(&key, &iv.0[..], &Uint8Array::new_with_length(0), &ct)
            .await?
            .to_vec();

        let msg: MessageAndSignature = bincode::deserialize(&plain).unwrap();
        let id = Identity::from(msg.sig.pol.derive::<IDENTITY_BYTES>().unwrap());
        let verified = self
            .verifier
            .chain(&msg.message)
            .verify(&self.vk.0, &msg.sig.sig, &id);

        if !verified {
            return Err(Error::IncorrectSignature);
        }

        debug_assert_eq!(self.config.message_len, msg.message.len());

        let res = Uint8Array::new_with_length(msg.message.len());
        res.copy_from(msg.message);

        Ok((res, msg.sig.pol))
    }
}

//impl Sealer<SealerMemoryConfig> {
//    /// Create a new [`Sealer`].
//    pub fn new<R: RngCore + CryptoRng>(
//        mpk: &PublicKey<CGWKV>,
//        policies: &EncryptionPolicy,
//        rng: &mut R,
//    ) -> Result<Self, Error> {
//        let (header, ss) = Header::new(mpk, policies, rng)?;
//        let Algorithm::Aes128Gcm(iv) = header.algo;
//
//        let mut key = [0u8; KEY_SIZE];
//        let mut nonce = [0u8; 12];
//        key.copy_from_slice(&ss.0[..KEY_SIZE]);
//        nonce.copy_from_slice(&iv.0[..12]);
//
//        Ok(Self {
//            header,
//            config: SealerMemoryConfig { key, nonce },
//        })
//    }
//
//    /// Seals the payload.
//    ///
//    /// See [`PostGuardPacket`] for serialization methods.
//    pub async fn seal(mut self, input: &Uint8Array) -> Result<PostGuardPacket, JsValue> {
//        self.header = self.header.with_mode(Mode::InMemory {
//            size: input.byte_length(),
//        });
//
//        let key = get_key(&self.config.key).await?;
//        let ciphertext = encrypt(
//            &key,
//            &self.config.nonce,
//            &Uint8Array::new_with_length(0),
//            input,
//        )
//        .await?
//        .to_vec();
//
//        Ok(PostGuardPacket {
//            version: VERSION_V2,
//            header: self.header,
//            ciphertext,
//        })
//    }
//}
//
//impl Unsealer<PostGuardPacket, UnsealerMemoryConfig> {
//    /// Blabla
//    pub async fn unseal(
//        self,
//        ident: &str,
//        usk: &UserSecretKey<CGWKV>,
//    ) -> Result<Uint8Array, JsValue> {
//        let rec_info = self
//            .header
//            .policies
//            .get(ident)
//            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;
//
//        let ss = rec_info.decaps(usk)?;
//        let key = get_key(&ss.0[..KEY_SIZE]).await?;
//
//        let Algorithm::Aes128Gcm(iv) = self.header.algo;
//
//        let ct = Uint8Array::new_with_length(
//            self.r
//                .ciphertext
//                .len()
//                .try_into()
//                .map_err(|_| Error::ConstraintViolation)?,
//        );
//        ct.copy_from(&self.r.ciphertext);
//
//        decrypt(&key, &iv.0[..], &Uint8Array::new_with_length(0), &ct).await
//    }
//}
