//! Streaming mode.

use super::aesgcm::{decrypt, encrypt, get_key};

use crate::artifacts::{PublicKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::{EncryptionPolicy, Policy};
use crate::util::preamble_checked;
use ibs::gg::{Identity, Signature, Signer, Verifier, IDENTITY_BYTES, SIG_BYTES};

use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use wasm_bindgen::{JsCast, JsValue};

use alloc::string::ToString;
use alloc::vec::Vec;

/// Configures an [`Sealer`] to process a payload stream.
#[derive(Debug)]
pub struct StreamSealerConfig {
    segment_size: u32,
    key: [u8; KEY_SIZE],
    nonce: [u8; STREAM_NONCE_SIZE],
}

/// Configures an [`Unsealer`] to process a payload stream.
#[derive(Debug)]
pub struct StreamUnsealerConfig {
    segment_size: u32,
    spill: Vec<u8>,
}

impl SealerConfig for StreamSealerConfig {}
impl UnsealerConfig for StreamUnsealerConfig {}
impl crate::client::sealed::SealerConfig for StreamSealerConfig {}
impl crate::client::sealed::UnsealerConfig for StreamUnsealerConfig {}

impl<'r, Rng: RngCore + CryptoRng> Sealer<'r, Rng, StreamSealerConfig> {
    /// Construct a new [`Sealer`] that can process payloads streamingly.
    pub fn new(
        pk: &PublicKey<CGWKV>,
        policies: &EncryptionPolicy,
        pub_sign_key: &SigningKeyExt,
        rng: &'r mut Rng,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(pk, policies, rng)?;

        let (segment_size, _) = stream_mode_checked(&header)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; STREAM_NONCE_SIZE];

        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..STREAM_NONCE_SIZE]);

        Ok(Sealer {
            rng,
            header,
            pub_sign_key: pub_sign_key.clone(),
            priv_sign_key: None,
            config: StreamSealerConfig {
                segment_size,
                key,
                nonce,
            },
        })
    }

    /// Seals payload data from a [`Stream`] of [`JsValue`] to a Sink of [`JsValue`].
    ///
    /// # Errors
    ///
    /// Make sure the [`JsValue`]s *can* dynamically be cast to [`Uint8Array`],
    /// otherwise this operation *will* error.
    pub async fn seal<R, W>(mut self, mut r: R, mut w: W) -> Result<(), Error>
    where
        R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
        W: Sink<JsValue, Error = JsValue> + Unpin,
    {
        let size_hint = r.size_hint();
        let new_hint = (size_hint.0 as u64, size_hint.1.map(|x| x as u64));

        self.header = self.header.with_mode(Mode::Streaming {
            segment_size: self.config.segment_size,
            size_hint: new_hint,
        });

        w.feed(Uint8Array::from(&PRELUDE[..]).into()).await?;
        w.feed(Uint8Array::from(&VERSION_V3.to_be_bytes()[..]).into())
            .await?;

        let header_vec = bincode::serialize(&self.header)?;

        w.feed(Uint8Array::from(&(header_vec.len() as u32).to_be_bytes()[..]).into())
            .await?;

        w.feed(Uint8Array::from(&header_vec[..]).into()).await?;

        let mut signer = Signer::default().chain(&header_vec);
        let header_sig = signer.clone().sign(&self.pub_sign_key.key.0, self.rng);
        let header_sig_ext = SignatureExt {
            sig: header_sig,
            pol: self.pub_sign_key.policy.clone(),
        };
        let header_sig_bytes = bincode::serialize(&header_sig_ext)?;

        w.feed(Uint8Array::from(&(header_sig_bytes.len() as u32).to_be_bytes()[..]).into())
            .await?;
        w.feed(Uint8Array::from(&header_sig_bytes[..]).into())
            .await?;

        let key = get_key(&self.config.key).await?;

        // Check for a private signing key, otherwise fall back to the public one.
        let signing_key = self.priv_sign_key.unwrap_or(self.pub_sign_key);

        let pol_bytes = bincode::serialize(&signing_key.policy)?;
        let pol_len: u32 = pol_bytes.len() as u32;

        if pol_len + POL_SIZE_SIZE as u32 > self.config.segment_size {
            return Err(Error::ConstraintViolation.into());
        }

        let buf = Uint8Array::new_with_length(self.config.segment_size + SIG_BYTES as u32);

        buf.set(
            &Uint8Array::from(&(pol_len as u32).to_be_bytes()[..]).into(),
            0,
        );
        buf.set(
            &Uint8Array::from(&pol_bytes[..]).into(),
            POL_SIZE_SIZE as u32,
        );

        let mut counter = 0u32;
        let mut buf_tail: u32 = POL_SIZE_SIZE as u32 + pol_len;
        let mut start: u32 = buf_tail;

        while let Some(Ok(data)) = r.next().await {
            let mut array: Uint8Array = data.dyn_into()?;

            while array.byte_length() != 0 {
                let len = array.byte_length();
                let rem = self.config.segment_size - buf_tail;

                if len < rem {
                    buf.set(&array, buf_tail);
                    array = Uint8Array::new_with_length(0);
                    buf_tail += len;
                } else {
                    buf.set(&array.slice(0, rem), buf_tail);
                    array = array.slice(rem, len);
                    buf_tail += rem;

                    signer.update(&buf.slice(start, buf_tail).to_vec());
                    let sig = signer.clone().sign(&signing_key.key.0, self.rng);
                    let sig_bytes = bincode::serialize(&sig)?;

                    buf.set(&Uint8Array::from(&sig_bytes[..]).into(), buf_tail);

                    let ct = encrypt(
                        &key,
                        &aead_nonce(&self.config.nonce, counter, false),
                        &Uint8Array::new_with_length(0),
                        &buf,
                    )
                    .await?;

                    w.feed(ct.into()).await?;

                    counter = counter.checked_add(1).ok_or(Error::Symmetric)?;
                    buf_tail = 0;
                    start = 0;
                }
            }
        }

        signer.update(&buf.slice(start, buf_tail).to_vec());
        let sig = signer.sign(&signing_key.key.0, self.rng);
        let sig_bytes = bincode::serialize(&sig)?;

        buf.set(&Uint8Array::from(&sig_bytes[..]).into(), buf_tail);
        buf_tail += SIG_BYTES as u32;

        let final_ct = encrypt(
            &key,
            &aead_nonce(&self.config.nonce, counter, true),
            &Uint8Array::new_with_length(0),
            &buf.slice(0, buf_tail),
        )
        .await?;

        w.feed(final_ct.into()).await?;

        w.flush().await?;
        w.close().await?;

        Ok(())
    }
}

// Nonce generation as defined in the STREAM construction.
fn aead_nonce(nonce: &[u8], counter: u32, last_block: bool) -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];

    iv[..STREAM_NONCE_SIZE].copy_from_slice(nonce);
    iv[STREAM_NONCE_SIZE..IV_SIZE - 1].copy_from_slice(&counter.to_be_bytes());
    iv[IV_SIZE - 1] = last_block as u8;

    iv
}

async fn read_atleast<R>(mut r: R, buf: &mut [u8], spill: &mut Vec<u8>) -> Result<(), Error>
where
    R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
{
    let buf_len = buf.len();
    let spill_len = spill.len();

    if buf_len <= spill_len {
        buf.copy_from_slice(&spill[..buf_len]);
        spill.drain(..buf_len);

        Ok(())
    } else {
        buf[..spill_len].copy_from_slice(&spill);
        let mut rem = buf_len - spill_len;
        spill.clear();

        while let Some(Ok(data)) = r.next().await {
            let arr: Uint8Array = data.dyn_into()?;
            let len = arr.byte_length();

            if len as usize >= rem {
                buf[buf_len - rem..].copy_from_slice(&arr.slice(0, rem as u32).to_vec()[..]);
                spill.extend_from_slice(&arr.slice(rem as u32, len).to_vec()[..]);
                rem = 0;
                break;
            } else {
                buf[buf_len - rem..buf_len - rem + len as usize].copy_from_slice(&arr.to_vec()[..]);
                rem -= len as usize;
            }
        }

        if rem == 0 {
            Ok(())
        } else {
            Err(Error::FormatViolation("unexpected EOF".to_string()).into())
        }
    }
}

impl<R> Unsealer<R, StreamUnsealerConfig>
where
    R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
{
    /// Create a new [`Unsealer`] that starts reading from a [`Stream<Item = Result<Uint8Array, JsValue>>`][Stream].
    ///
    /// # Errors
    ///
    /// Errors if the bytestream is not a legitimate PostGuard bytestream.
    /// Also errors if the items (of type [`JsValue`]) cannot be cast into [`Uint8Array`].
    pub async fn new(mut r: R, vk: &VerifyingKey) -> Result<Self, Error> {
        let mut spill = Vec::new();

        let mut preamble = [0u8; PREAMBLE_SIZE];
        read_atleast(&mut r, &mut preamble, &mut spill).await?;
        let (version, header_len) = preamble_checked(&preamble)?;

        let mut header_raw = vec![0u8; header_len];
        read_atleast(&mut r, &mut header_raw, &mut spill).await?;

        let mut h_sig_len_bytes = [0u8; SIG_SIZE_SIZE];
        read_atleast(&mut r, &mut h_sig_len_bytes, &mut spill).await?;
        let header_sig_len = u32::from_be_bytes(h_sig_len_bytes);

        let mut header_sig_raw = vec![0u8; header_sig_len as usize];
        read_atleast(&mut r, &mut header_sig_raw, &mut spill).await?;
        let h_sig_ext: SignatureExt = bincode::deserialize(&header_sig_raw)?;

        let verifier = Verifier::default().chain(&header_raw);
        let pub_id = h_sig_ext.pol.derive_ibs()?;

        if !verifier.clone().verify(&vk.0, &h_sig_ext.sig, &pub_id) {
            return Err(Error::IncorrectSignature.into());
        }

        let header: Header = bincode::deserialize(&header_raw)?;
        let (segment_size, _) = stream_mode_checked(&header)?;

        Ok(Unsealer {
            version,
            header,
            pub_id: h_sig_ext.pol,
            verifier,
            vk: vk.clone(),
            r,
            config: StreamUnsealerConfig {
                spill,
                segment_size,
            },
        })
    }

    /// Unseal into an [`Sink<Uint8Array, Error = JsValue>`][Sink].
    pub async fn unseal<W>(
        &mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<VerificationResult, Error>
    where
        W: Sink<JsValue, Error = JsValue> + Unpin,
    {
        let rec_info = self
            .header
            .recipients
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let Algorithm::Aes128Gcm(iv) = self.header.algo;
        let nonce = &iv.0[..STREAM_NONCE_SIZE];

        let segment_size: u32 = self.config.segment_size + (SIG_BYTES + TAG_SIZE) as u32;

        let buf = Uint8Array::new_with_length(segment_size);
        let mut counter = 0u32;
        let mut buf_tail = 0;
        let mut pol_id: Option<(Policy, Identity)> = None;

        fn extract_policy(
            plain: Uint8Array,
        ) -> Result<(Option<(Policy, Identity)>, Uint8Array), Error> {
            let pol_len =
                u32::from_be_bytes(plain.slice(0, POL_SIZE_SIZE as u32).to_vec()[..].try_into()?);
            let pol_bytes = plain.slice(POL_SIZE_SIZE as u32, POL_SIZE_SIZE as u32 + pol_len);
            let pol: Policy = bincode::deserialize(&pol_bytes.to_vec())?;
            let id = pol.derive_ibs()?;
            let new_plain = plain.slice(POL_SIZE_SIZE as u32 + pol_len, plain.byte_length());

            Ok((Some((pol, id)), new_plain))
        }

        loop {
            // First exhaust the spillage, then the rest of the stream.
            let mut array: Uint8Array = if !self.config.spill.is_empty() {
                let arr = Uint8Array::from(&self.config.spill[..]);
                self.config.spill.clear();
                arr
            } else if let Some(Ok(data)) = self.r.next().await {
                data.dyn_into()?
            } else {
                break;
            };

            while array.byte_length() != 0 {
                let len = array.byte_length();
                let rem = buf.byte_length() - buf_tail;

                if len < rem {
                    buf.set(&array, buf_tail);
                    array = Uint8Array::new_with_length(0);
                    buf_tail += len;
                } else {
                    buf.set(&array.slice(0, rem), buf_tail);
                    array = array.slice(rem, len);

                    let mut plain = decrypt(
                        &key,
                        &aead_nonce(nonce, counter, false),
                        &Uint8Array::new_with_length(0),
                        &buf,
                    )
                    .await?;

                    if counter == 0 {
                        (pol_id, plain) = extract_policy(plain)?;
                    }

                    debug_assert!(plain.byte_length() > SIG_BYTES as u32);

                    let m = plain.slice(0, plain.byte_length() - SIG_BYTES as u32);
                    let sig =
                        plain.slice(plain.byte_length() - SIG_BYTES as u32, plain.byte_length());
                    let sig: Signature = bincode::deserialize(&sig.to_vec())?;

                    self.verifier.update(&m.to_vec());

                    if !self
                        .verifier
                        .clone()
                        .verify(&self.vk.0, &sig, &pol_id.as_ref().unwrap().1)
                    {
                        return Err(Error::IncorrectSignature.into());
                    }

                    w.feed(m.into()).await?;

                    counter = counter.checked_add(1).ok_or(Error::Symmetric)?;
                    buf_tail = 0;
                }
            }
        }

        let mut final_plain = decrypt(
            &key,
            &aead_nonce(nonce, counter, true),
            &Uint8Array::new_with_length(0),
            &buf.slice(0, buf_tail),
        )
        .await?;

        if counter == 0 {
            (pol_id, final_plain) = extract_policy(final_plain)?;
        }

        debug_assert!(final_plain.byte_length() > SIG_BYTES as u32);
        let m = final_plain.slice(0, final_plain.byte_length() - SIG_BYTES as u32);
        let sig = final_plain.slice(
            final_plain.byte_length() - SIG_BYTES as u32,
            final_plain.byte_length(),
        );

        let sig: Signature = bincode::deserialize(&sig.to_vec())?;
        self.verifier.update(&m.to_vec());
        if !self
            .verifier
            .clone()
            .verify(&self.vk.0, &sig, &pol_id.as_ref().unwrap().1)
        {
            return Err(Error::IncorrectSignature.into());
        }

        w.feed(m.into()).await?;

        w.flush().await?;
        w.close().await?;

        let private_id = pol_id.unwrap().0;
        let private = if self.pub_id == private_id {
            None
        } else {
            Some(private_id)
        };

        Ok(VerificationResult {
            public: self.pub_id.clone(),
            private,
        })
    }
}
