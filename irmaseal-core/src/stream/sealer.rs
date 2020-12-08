use core::convert::TryFrom;
use futures::{AsyncReadExt, AsyncWriteExt};
use hmac::Mac;
use postcard::to_slice;
use rand::{CryptoRng, RngCore};

use crate::stream::*;
use crate::Error::{ReadError, WriteError};
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, Rng: CryptoRng + RngCore> {
    pk: &'a PublicKey,
    rng: &'a mut Rng,
}

impl<'a, Rng: CryptoRng + RngCore> Sealer<'a, Rng> {
    pub fn new(pk: &'a PublicKey, rng: &'a mut Rng) -> Sealer<'a, Rng> {
        Sealer { pk, rng }
    }

    async fn prepare_for_seal<W: AsyncWrite + Unpin>(
        &mut self,
        i: Identity,
        mut w: W,
    ) -> Result<(SymCrypt, Verifier), Error> {
        let derived = i.derive()?;
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&self.pk.0, &derived, self.rng);

        let (aeskey, mackey) = crate::stream::util::derive_keys(&k);
        let iv = crate::stream::util::generate_iv(self.rng);

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

        Ok((aes, hmac))
    }

    pub async fn seal<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        i: Identity,
        mut r: R,
        mut w: W,
    ) -> Result<(), Error> {
        let (mut aes, mut hmac) = self.prepare_for_seal(i, &mut w).await?;

        let mut buf = [0u8; BLOCKSIZE];

        loop {
            let input_length = r.read(&mut buf).map_err(|err| ReadError(err)).await?;
            if input_length == 0 {
                break;
            }
            let data = &mut buf[..input_length];

            // Encrypt-then-MAC
            aes.encrypt(data).await;
            hmac.input(data);

            w.write_all(data).map_err(|err| WriteError(err)).await?;
        }

        let code = hmac.result_reset().code();
        w.write_all(&code).map_err(|err| WriteError(err)).await
    }
}
