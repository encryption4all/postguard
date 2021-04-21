use crate::stream::util::ArchiveReader;
use crate::stream::*;
use crate::*;

use arrayref::array_ref;
use core::convert::TryInto;
use ctr::stream_cipher::{NewStreamCipher, StreamCipher};
use hmac::Mac;

/// First stage opener of an IRMAseal encrypted bytestream.
/// It reads the IRMAseal header, and yields the recipient Identity for which the content is intended.
///
/// Enables the library user to lookup the UserSecretKey corresponding to this Identity before continuing.
pub struct OpenerSealed<R: Readable> {
    ar: ArchiveReader<R, [u8; MAX_METADATA_SIZE]>,
}

/// Second stage opener of an IRMAseal encrypted bytestream.
///
/// **Warning**: will only validate the authenticity of the plaintext when calling `validate`.
pub struct OpenerUnsealed<R: Readable> {
    aes: SymCrypt,
    hmac: Verifier,
    r: R,
    resultbuf: Option<[u8; BLOCKSIZE]>,
}

impl<R: Readable> OpenerSealed<R> {
    /// Starts interpreting a bytestream as an IRMAseal stream.
    /// Will immediately detect whether the bytestream actually is such a stream, and will yield
    /// the identity for which the stream is intended, as well as the stream continuation.
    pub fn new(r: R) -> Result<(Metadata, OpenerSealed<R>), Error> {
        let mut ar = ArchiveReader::<R, [u8; MAX_METADATA_SIZE]>::new(r);

        let prelude = ar.read_bytes_strict(PRELUDE.len())?;
        if prelude != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let _version = u16::from_be_bytes(
            ar.read_bytes_strict(core::mem::size_of::<u16>())?
                .try_into()
                .unwrap(),
        );
        // Later we can do different things here depending on the version.

        let meta_len = u16::from_be_bytes(
            ar.read_bytes_strict(core::mem::size_of::<u16>())?
                .try_into()
                .unwrap(),
        );
        if usize::from(meta_len) > MAX_METADATA_SIZE {
            return Err(Error::FormatViolation);
        }

        let metadata_buf = ar.read_bytes_strict(meta_len.into())?;

        let metadata = postcard::from_bytes(metadata_buf).or(Err(Error::FormatViolation))?;

        Ok((metadata, OpenerSealed { ar }))
    }

    /// Will unseal the stream continuation and yield a plaintext bytestream.
    pub fn unseal(
        self,
        metadata: &Metadata,
        usk: &UserSecretKey,
    ) -> Result<OpenerUnsealed<R>, Error> {
        let c = crate::util::open_ct(ibe::kiltz_vahlis_one::CipherText::from_bytes(array_ref!(
            metadata.ciphertext.as_slice(),
            0,
            CIPHERTEXT_SIZE
        )))
        .ok_or(Error::FormatViolation)?;

        let m = ibe::kiltz_vahlis_one::decrypt(&usk.0, &c);
        let (skey, mackey) = crate::stream::util::derive_keys(&m);

        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let (headerbuf, r) = self.ar.disclose();
        hmac.input(&headerbuf);

        let iv: &[u8; IVSIZE] = array_ref!(metadata.iv.as_slice(), 0, IVSIZE);

        let aes = SymCrypt::new(&skey.into(), &(*iv).into());

        Ok(OpenerUnsealed {
            aes,
            hmac,
            r,
            resultbuf: None,
        })
    }
}

impl<R: Readable> OpenerUnsealed<R> {
    /// Read up to `BLOCKSIZE` bytes at a time.
    pub fn read(&mut self) -> Result<&[u8], Error> {
        let (resultsize, macbuf) = match self.resultbuf.as_mut() {
            None => (BLOCKSIZE, None),
            Some(dst) => {
                let mut macbuf = [0u8; MACSIZE];
                macbuf.copy_from_slice(&dst[BLOCKSIZE - MACSIZE..BLOCKSIZE]);
                (BLOCKSIZE - MACSIZE, Some(macbuf))
            }
        };

        // TODO eliminate extra check.
        let dst = self.resultbuf.get_or_insert_with(|| [0u8; BLOCKSIZE]);
        let src = self.r.read_bytes(resultsize)?;
        let srcsize = src.len();

        if srcsize == 0 {
            return Err(Error::EndOfStream);
        }

        let dstmid = BLOCKSIZE - srcsize;
        dst[dstmid..BLOCKSIZE].copy_from_slice(src);

        let dststart = match macbuf {
            None => dstmid,
            Some(macbuf) => {
                let dststart = dstmid - MACSIZE;
                dst[dststart..dstmid].copy_from_slice(&macbuf);
                dststart
            }
        };

        let mut content = &mut dst[dststart..BLOCKSIZE - MACSIZE];
        self.hmac.input(content);
        self.aes.decrypt(&mut content);

        Ok(content)
    }

    /// Will check the HMAC once the entire stream is exhausted.
    /// Will only yield the correct value once the **entire** stream is read
    /// using `write_to`, or by manually calling `write` until `Error::EndOfStream` is yielded.
    pub fn validate(self) -> bool {
        match self.resultbuf {
            None => false,
            Some(resultbuf) => {
                let macbuf = &resultbuf[BLOCKSIZE - MACSIZE..BLOCKSIZE];
                self.hmac.verify(macbuf).is_ok()
            }
        }
    }

    /// Will block and write the entire stream to the argument writer.
    pub fn write_to<W: Writable>(&mut self, w: &mut W) -> Result<(), Error> {
        loop {
            match self.read() {
                Ok(buf) => w.write(buf)?,
                Err(Error::EndOfStream) => return Ok(()),
                Err(e) => return Err(e),
            };
        }
    }
}
