use core::convert::TryFrom;
use futures::{AsyncReadExt, AsyncWriteExt};
use hmac::Mac;
use postcard::to_slice;
use rand::{CryptoRng, Rng};

use crate::stream::*;
use crate::Error::{ReadError, WriteError};
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<W: AsyncWrite + Unpin> {
    aes: SymCrypt,
    hmac: Verifier,
    output_writer: W,
}

impl<W: AsyncWrite + Unpin> Sealer<W> {
    pub async fn new<R: Rng + CryptoRng>(
        i: Identity,
        pk: &PublicKey,
        rng: &mut R,
        mut w: W,
    ) -> Result<Self, Error> {
        let derived = i.derive()?;
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &derived, rng);

        let (aeskey, mackey) = crate::stream::util::derive_keys(&k);
        let iv = crate::stream::util::generate_iv(rng);

        let aes = SymCrypt::new(&aeskey.into(), &iv.into()).await;
        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let ciphertext = c.to_bytes();

        let metadata = Metadata::new(Version::V1_0, &ciphertext, &iv, i)?;
        let mut deser_buf = [0u8; MAX_METADATA_SIZE];
        let meta_bytes = to_slice(&metadata, &mut deser_buf).or(Err(Error::FormatViolation))?;

        let metadata_len = u16::try_from(meta_bytes.len())
            .or(Err(Error::FormatViolation))?
            .to_be_bytes();

        hmac.input(&PRELUDE);
        w.write_all(&PRELUDE).map_err(|e| WriteError(e)).await?;

        hmac.input(&metadata_len);
        w.write_all(&metadata_len)
            .map_err(|e| WriteError(e))
            .await?;

        hmac.input(meta_bytes);
        w.write_all(meta_bytes).map_err(|e| WriteError(e)).await?;

        if metadata_len.len() > MAX_METADATA_SIZE {
            Err(Error::FormatViolation)
        } else {
            Ok(Sealer {
                aes,
                hmac,
                output_writer: w,
            })
        }
    }

    pub async fn seal<R: AsyncRead + Unpin>(&mut self, mut r: R) -> Result<(), Error> {
        let mut buf = [0u8; BLOCKSIZE];

        loop {
            let input_length = r.read(&mut buf).map_err(|err| ReadError(err)).await?;
            if input_length == 0 {
                break;
            }
            let data = &mut buf[..input_length];

            // Encrypt-then-MAC
            self.aes.encrypt(data).await;
            self.hmac.input(data);

            self.output_writer
                .write_all(data)
                .map_err(|err| WriteError(err))
                .await?;
        }

        let code = self.hmac.result_reset().code();
        self.output_writer
            .write_all(&code)
            .map_err(|err| WriteError(err))
            .await
    }
}
