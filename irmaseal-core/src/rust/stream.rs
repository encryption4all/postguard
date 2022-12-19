//! Streaming mode.

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::consts::*;
use crate::error::Error;
use crate::header::*;
use crate::identity::Policy;
use crate::util::{stream, *};
use crate::{Sealer, SealerConfig, Unsealer, UnsealerConfig};

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aead::KeyInit;
use aes_gcm::Aes128Gcm;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use ibe::kem::cgw_kv::CGWKV;
use rand::{CryptoRng, RngCore};

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
}

impl SealerConfig for StreamSealerConfig {}
impl UnsealerConfig for StreamUnsealerConfig {}
impl crate::sealed::SealerConfig for StreamSealerConfig {}
impl crate::sealed::UnsealerConfig for StreamUnsealerConfig {}

impl Sealer<StreamSealerConfig> {
    /// Construct a new [`Sealer`] that can process payloads streamingly.
    pub fn new<Rng: RngCore + CryptoRng>(
        pk: &PublicKey<CGWKV>,
        policies: &Policy,
        rng: &mut Rng,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(pk, policies, rng)?;

        let (segment_size, _) = stream::mode_checked(&header)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; STREAM_NONCE_SIZE];

        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..STREAM_NONCE_SIZE]);

        Ok(Sealer {
            header,
            config: StreamSealerConfig {
                segment_size,
                key,
                nonce,
            },
        })
    }

    /// Add a size hint (optionally).
    ///
    /// This can help the receiver save some reallocations.
    pub fn with_size_hint(mut self, size_hint: (u64, Option<u64>)) -> Self {
        self.header.mode = Mode::Streaming {
            segment_size: self.config.segment_size,
            size_hint,
        };

        self
    }

    /// Seals payload data from an [`AsyncRead`] into an [`AsyncWrite`].
    pub async fn seal<R, W>(self, mut r: R, mut w: W) -> Result<(), Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        w.write_all(&PRELUDE).await?;
        w.write_all(&VERSION_V2.to_be_bytes()).await?;

        let mut header_vec = Vec::with_capacity(MAX_HEADER_SIZE);
        self.header.into_bytes(&mut header_vec)?;

        w.write_all(
            &u32::try_from(header_vec.len())
                .map_err(|_e| Error::ConstraintViolation)?
                .to_be_bytes(),
        )
        .await?;

        w.write_all(&header_vec[..]).await?;

        let aead = Aes128Gcm::new_from_slice(&self.config.key).map_err(|_e| Error::KeyError)?;
        let mut enc = EncryptorBE32::from_aead(aead, &self.config.nonce.into());

        let mut buf = vec![0; self.config.segment_size as usize];
        let mut buf_tail: usize = 0;

        buf.reserve(TAG_SIZE);

        loop {
            let read = r
                .read(&mut buf[buf_tail..self.config.segment_size as usize])
                .await?;
            buf_tail += read;

            if buf_tail == self.config.segment_size as usize {
                buf.truncate(buf_tail);
                enc.encrypt_next_in_place(b"", &mut buf)
                    .map_err(|_e| Error::Symmetric)?;
                w.write_all(&buf[..]).await?;
                buf_tail = 0;
            } else if read == 0 {
                buf.truncate(buf_tail);
                enc.encrypt_last_in_place(b"", &mut buf)
                    .map_err(|_e| Error::Symmetric)?;
                w.write_all(&buf[..]).await?;
                break;
            }
        }

        w.close().await?;

        Ok(())
    }
}

impl<R> Unsealer<R, StreamUnsealerConfig>
where
    R: AsyncRead + Unpin,
{
    /// Create a new [`Unsealer`] that starts reading from an [`AsyncRead`].
    ///
    /// Errors if the bytestream is not a legitimate IRMAseal bytestream.
    pub async fn new(mut r: R) -> Result<Self, Error> {
        let mut preamble = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut preamble)
            .map_err(|_e| Error::NotIRMASEAL)
            .await?;

        let (version, header_len) = preamble_checked(&preamble)?;

        let mut header_raw = Vec::with_capacity(header_len);

        // Limit reader to not read past header
        let mut r = r.take(header_len as u64);

        r.read_to_end(&mut header_raw)
            .map_err(|_e| Error::ConstraintViolation)
            .await?;

        let header = Header::from_bytes(&*header_raw)?;

        let (segment_size, _) = stream::mode_checked(&header)?;

        Ok(Unsealer {
            version,
            header,
            config: StreamUnsealerConfig { segment_size },
            r: r.into_inner(), // This (new) reader is locked to the payload.
        })
    }

    /// Unseal the remaining data (which is now only payload) into an [`AsyncWrite`].
    pub async fn unseal<W: AsyncWrite + Unpin>(
        &mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<(), Error> {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = &ss.0[..KEY_SIZE];
        let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;

        let Algorithm::Aes128Gcm(iv) = self.header.algo;
        let nonce = &iv.0[..STREAM_NONCE_SIZE];

        let mut dec = DecryptorBE32::from_aead(aead, nonce.into());

        let bufsize: usize = self.config.segment_size as usize + TAG_SIZE;
        let mut buf = vec![0u8; bufsize];
        let mut buf_tail = 0;

        loop {
            let read = self.r.read(&mut buf[buf_tail..bufsize]).await?;
            buf_tail += read;

            if buf_tail == bufsize {
                dec.decrypt_next_in_place(b"", &mut buf)
                    .map_err(|_e| Error::Symmetric)?;
                w.write_all(&buf[..]).await?;

                buf_tail = 0;
                buf.resize(bufsize, 0);
            } else if read == 0 {
                buf.truncate(buf_tail);
                dec.decrypt_last_in_place(b"", &mut buf)
                    .map_err(|_e| Error::Symmetric)?;
                w.write_all(&buf[..]).await?;
                break;
            }
        }

        w.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestSetup;
    use crate::SYMMETRIC_CRYPTO_DEFAULT_CHUNK;
    use futures::{executor::block_on, io::AllowStdIo};
    use rand::RngCore;
    use std::io::Cursor;

    const LENGTHS: &[u32] = &[
        1,
        512,
        SYMMETRIC_CRYPTO_DEFAULT_CHUNK - 3,
        SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
        SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 3,
        3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
        3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 16,
        3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK - 17,
    ];

    fn seal_helper(setup: &TestSetup, plain: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let mut input = AllowStdIo::new(Cursor::new(plain));
        let mut output = AllowStdIo::new(Vec::new());

        block_on(async {
            Sealer::<StreamSealerConfig>::new(&setup.mpk, &setup.policy, &mut rng)
                .unwrap()
                .seal(&mut input, &mut output)
                .await
                .unwrap();
        });

        output.into_inner()
    }

    fn unseal_helper(setup: &TestSetup, ct: &[u8], recipient_idx: usize) -> Vec<u8> {
        let mut input = AllowStdIo::new(Cursor::new(ct));
        let mut output = AllowStdIo::new(Vec::new());

        let ids: Vec<String> = setup.policy.keys().cloned().collect();
        let id = &ids[recipient_idx];
        let usk_id = setup.usks.get(id).unwrap();

        block_on(async {
            let mut unsealer = Unsealer::<_, StreamUnsealerConfig>::new(&mut input)
                .await
                .unwrap();

            // Normally, a user would need to retrieve a usk here via the PKG,
            // but in this case we own the master key pair.
            unsealer.unseal(id, usk_id, &mut output).await.unwrap();
        });

        output.into_inner()
    }

    fn seal_and_unseal(setup: &TestSetup, plain: Vec<u8>) {
        let ct = seal_helper(setup, &plain);
        let plain2 = unseal_helper(setup, &ct, 0);

        assert_eq!(&plain, &plain2);
    }

    fn rand_vec(length: usize) -> Vec<u8> {
        let mut vec = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut vec);
        vec
    }

    #[test]
    fn test_reflection_seal_unsealer() {
        let setup = TestSetup::default();

        for l in LENGTHS {
            seal_and_unseal(&setup, rand_vec(*l as usize));
        }
    }

    #[test]
    #[should_panic]
    fn test_corrupt_body() {
        let setup = TestSetup::default();

        let plain = rand_vec(100);
        let mut ct = seal_helper(&setup, &plain);

        // Flip a byte that is guaranteed to be in the encrypted payload.
        let ct_len = ct.len();
        ct[ct_len - 5] = !ct[ct_len - 5];

        // This should panic.
        let _plain2 = unseal_helper(&setup, &ct, 1);
    }

    #[test]
    #[should_panic]
    fn test_corrupt_tag() {
        let setup = TestSetup::default();

        let plain = rand_vec(100);
        let mut ct = seal_helper(&setup, &plain);

        let len = ct.len();
        ct[len - 5] = !ct[len - 5];

        // This should panic as well.
        let _plain2 = unseal_helper(&setup, &ct, 1);
    }
}
