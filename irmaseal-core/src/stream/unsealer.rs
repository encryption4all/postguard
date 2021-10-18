use crate::*;
use crate::{stream::*, util::KeySet};
use ctr::cipher::{NewCipher, StreamCipher};
use digest::Digest;
use ibe::kem::cgw_fo::CGWFO;

#[cfg(feature = "v1")]
mod v1 {
    use super::*;
    use crate::metadata::v1::V1Metadata;
    use core::convert::TryInto;
    use ibe::kem::kiltz_vahlis_one::KV1;

    impl<R: Readable> Unsealer<R> {
        pub fn new_v1(
            metadata: &V1Metadata,
            header: HeaderBuf,
            usk: &UserSecretKey<KV1>,
            r: R,
        ) -> Result<Unsealer<R>, Error> {
            let KeySet { aes_key, mac_key } = metadata.derive_keys(usk)?;

            let mut mac = Mac::default();
            mac.input(&mac_key);
            mac.input(&header);

            let iv: [u8; IV_SIZE] = metadata.iv.as_slice().try_into().unwrap();

            let decrypter = SymCrypt::new(&aes_key.into(), &iv.into());

            Ok(Unsealer {
                decrypter,
                mac,
                r,
                resultbuf: None,
            })
        }
    }
}

/// Unseal IRMAseal encrypted bytestream.
///
/// **Warning**: will only validate the authenticity of the plaintext when calling `validate`.
pub struct Unsealer<R: Readable> {
    decrypter: SymCrypt,
    mac: Mac,
    r: R,
    resultbuf: Option<[u8; SYMMETRIC_CRYPTO_BLOCKSIZE]>,
}

impl<R: Readable> Unsealer<R> {
    pub fn new_v2(
        metadata: &V2Metadata,
        header: HeaderBuf,
        usk: &UserSecretKey<CGWFO>,
        mpk: &PublicKey<CGWFO>,
        r: R,
    ) -> Result<Unsealer<R>, Error> {
        let KeySet { aes_key, mac_key } = metadata.derive_keys(usk, mpk)?;

        let mut mac = Mac::default();
        mac.input(&mac_key);
        mac.input(&header);

        let decrypter = SymCrypt::new(&aes_key.into(), &metadata.iv.into());

        Ok(Unsealer {
            decrypter,
            mac,
            r,
            resultbuf: None,
        })
    }
}

impl<R: Readable> Unsealer<R> {
    /// Read up to `SYMMETRIC_CRYPTO_BLOCKSIZE` bytes at a time.
    pub fn read(&mut self) -> Result<&[u8], StreamError> {
        let (resultsize, macbuf) = match self.resultbuf.as_mut() {
            None => (SYMMETRIC_CRYPTO_BLOCKSIZE, None),
            Some(dst) => {
                let mut macbuf = [0u8; MAC_SIZE];
                macbuf.copy_from_slice(
                    &dst[SYMMETRIC_CRYPTO_BLOCKSIZE - MAC_SIZE..SYMMETRIC_CRYPTO_BLOCKSIZE],
                );
                (SYMMETRIC_CRYPTO_BLOCKSIZE - MAC_SIZE, Some(macbuf))
            }
        };

        // TODO eliminate extra check.
        let dst = self
            .resultbuf
            .get_or_insert_with(|| [0u8; SYMMETRIC_CRYPTO_BLOCKSIZE]);
        let src = self.r.read_bytes(resultsize)?;
        let srcsize = src.len();

        if srcsize == 0 {
            return Err(StreamError::EndOfStream);
        }

        let dstmid = SYMMETRIC_CRYPTO_BLOCKSIZE - srcsize;
        dst[dstmid..SYMMETRIC_CRYPTO_BLOCKSIZE].copy_from_slice(src);

        let dststart = match macbuf {
            None => dstmid,
            Some(macbuf) => {
                let dststart = dstmid - MAC_SIZE;
                dst[dststart..dstmid].copy_from_slice(&macbuf);
                dststart
            }
        };

        let mut content = &mut dst[dststart..SYMMETRIC_CRYPTO_BLOCKSIZE - MAC_SIZE];
        self.mac.input(&content);
        self.decrypter.apply_keystream(&mut content);

        Ok(content)
    }

    /// Will check the tag once the entire stream is exhausted.
    /// Will only yield the correct value once the **entire** stream is read
    /// using `write_to`, or by manually calling `write` until `Error::EndOfStream` is yielded.
    pub fn validate(self) -> bool {
        match self.resultbuf {
            None => false,
            Some(resultbuf) => {
                let expected =
                    &resultbuf[SYMMETRIC_CRYPTO_BLOCKSIZE - MAC_SIZE..SYMMETRIC_CRYPTO_BLOCKSIZE];
                let got = self.mac.result();
                expected == got.as_slice()
            }
        }
    }

    /// Will block and write the entire stream to the argument writer.
    pub fn write_to<W: Writable>(&mut self, w: &mut W) -> Result<(), StreamError> {
        loop {
            match self.read() {
                Ok(buf) => w.write(buf)?,
                Err(StreamError::EndOfStream) => return Ok(()),
                Err(e) => return Err(e),
            };
        }
    }
}
