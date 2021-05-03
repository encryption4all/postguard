use crate::*;
use crate::{stream::*, util::KeySet};

use arrayref::array_ref;
use ctr::cipher::{NewCipher, StreamCipher};
use digest::Digest;
/// Unseal IRMAseal encrypted bytestream.
///
/// **Warning**: will only validate the authenticity of the plaintext when calling `validate`.
pub struct Unsealer<R: Readable> {
    decrypter: SymCrypt,
    verifier: Verifier,
    r: R,
    resultbuf: Option<[u8; SYMMETRIC_CRYPTO_BLOCKSIZE]>,
}

impl<R: Readable> Unsealer<R> {
    pub fn new(
        metadata: &Metadata,
        header: HeaderBuf,
        usk: &UserSecretKey,
        r: R,
    ) -> Result<Unsealer<R>, Error> {
        let KeySet { aes_key, mac_key } = metadata.derive_keys(usk)?;

        let mut verifier = Verifier::default();
        verifier.input(&mac_key);
        verifier.input(&header);

        let iv: &[u8; IVSIZE] = array_ref!(metadata.iv.as_slice(), 0, IVSIZE);

        let decrypter = SymCrypt::new(&aes_key.into(), &(*iv).into());

        Ok(Unsealer {
            decrypter,
            verifier,
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
        self.verifier.input(&content);
        self.decrypter.apply_keystream(&mut content);

        Ok(content)
    }

    /// Will check the HMAC once the entire stream is exhausted.
    /// Will only yield the correct value once the **entire** stream is read
    /// using `write_to`, or by manually calling `write` until `Error::EndOfStream` is yielded.
    pub fn validate(self) -> bool {
        match self.resultbuf {
            None => false,
            Some(resultbuf) => {
                let expected =
                    &resultbuf[SYMMETRIC_CRYPTO_BLOCKSIZE - MAC_SIZE..SYMMETRIC_CRYPTO_BLOCKSIZE];
                let got = self.verifier.result();
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
