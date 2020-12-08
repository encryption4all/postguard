use crate::stream::*;
use crate::*;

use arrayref::array_ref;
use arrayvec::ArrayVec;
use core::convert::TryFrom;
use core::convert::TryInto;
use hmac::Mac;

/// Opener of an IRMAseal encrypted bytestream.
/// It reads the IRMAseal header and other metadata from the bytestream and
/// yields an OpenerSealed instance.
///
/// OpenerSealed offers the get_identity method to enable the library user
/// to retrieve the Identity of the recipient for whom the bytestream is encrypted.
///
/// Using the Identity, the library user is able to lookup the UserSecretKey corresponding
/// to the recipient's Identity. OpenerSealed then offers the unseal method to start decrypting
/// the encrypted content of the bytestream and write this to the given writer.
pub struct OpenerSealed<R: AsyncRead + Unpin> {
    r: R,
    metadata: Metadata,
    metadata_buf: ArrayVec<[u8; MAX_METADATA_SIZE]>,
}

impl<R: AsyncRead + Unpin> OpenerSealed<R> {
    /// Starts interpreting a bytestream as an IRMAseal stream.
    /// Will immediately detect whether the bytestream actually is such a stream.
    pub async fn new(mut r: R) -> Result<Self, Error> {
        let mut buffer = [0u8; 4 + core::mem::size_of::<u16>()];
        r.read_exact(&mut buffer)
            .map_err(|err| Error::ReadError(err))
            .await?;

        if buffer[..4] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let meta_len = usize::from(u16::from_be_bytes(buffer[4..].try_into().unwrap()));
        if meta_len > MAX_METADATA_SIZE {
            return Err(Error::FormatViolation);
        }

        let mut metadata_buf: ArrayVec<[u8; MAX_METADATA_SIZE]> = ArrayVec::new();
        unsafe {
            // set_len can only fail when the length is greater than MAX_METADATA_SIZE
            // and we explicitly check on this case above, so this cannot happen.
            metadata_buf.set_len(meta_len);
        }
        r.read_exact(metadata_buf.as_mut_slice())
            .map_err(|err| Error::ReadError(err))
            .await?;

        let metadata =
            postcard::from_bytes(metadata_buf.as_slice()).or(Err(Error::FormatViolation))?;

        Ok(OpenerSealed {
            r,
            metadata,
            metadata_buf,
        })
    }

    /// Will return the recipient Identity for which this stream is encrypted.
    /// This Identity can be used to derive the right UserSecretKey for unseal.
    pub fn get_identity(&self) -> &Identity {
        &self.metadata.identity
    }

    /// Will unseal the encrypted bytestream, write the plaintext in the given async writer
    /// and returns whether the integrity of the decryption is valid.
    /// Method consumes OpenerSealed since it fully decrypts the encrypted
    /// bytestream from the async reader within.
    pub async fn unseal<W: AsyncWrite + Unpin>(
        mut self,
        usk: &UserSecretKey,
        mut w: W,
    ) -> Result<bool, Error> {
        let c = crate::util::open_ct(ibe::kiltz_vahlis_one::CipherText::from_bytes(array_ref!(
            self.metadata.ciphertext.as_slice(),
            0,
            CIPHERTEXT_SIZE
        )))
        .ok_or(Error::FormatViolation)?;

        let m = ibe::kiltz_vahlis_one::decrypt(&usk.0, &c);
        let (skey, mackey) = crate::stream::util::derive_keys(&m);

        let mut hmac = Verifier::new_varkey(&mackey).unwrap();
        hmac.input(&PRELUDE);
        let metadata_len = u16::try_from(self.metadata_buf.len())
            .or(Err(Error::FormatViolation))?
            .to_be_bytes();
        hmac.input(&metadata_len);

        let iv: &[u8; IVSIZE] = array_ref!(self.metadata.iv.as_slice(), 0, IVSIZE);

        hmac.input(self.metadata_buf.as_slice());

        let mut aes = SymCrypt::new(&skey.into(), &iv).await;
        let mut buf = [0u8; BLOCKSIZE + MACSIZE];

        // The input buffer must at least contain enough bytes for a MAC to be included.
        self.r
            .read_exact(&mut buf[..MACSIZE])
            .map_err(|err| Error::ReadError(err))
            .await?;

        let mut buf_tail = MACSIZE;
        loop {
            let input_length = self
                .r
                .read(&mut buf[buf_tail..])
                .map_err(|err| Error::ReadError(err))
                .await?;
            buf_tail += input_length;

            // Start encrypting when we have read enough data to put aside a new MAC
            // or when we have hit EOF when reading and we still have data left to encrypt.
            if buf_tail >= 2 * MACSIZE || input_length == 0 && buf_tail > MACSIZE {
                let mut block = &mut buf[0..buf_tail - MACSIZE];

                // Decrypt according to encrypt-than-MAC
                hmac.input(&mut block);
                aes.decrypt(&mut block).await;

                w.write_all(&mut block)
                    .map_err(|err| Error::WriteError(err))
                    .await?;

                // Make sure potential MAC is shifted to the front of the array.
                let mut tmp = [0u8; MACSIZE];
                tmp.copy_from_slice(&buf[buf_tail - MACSIZE..buf_tail]);
                buf[..MACSIZE].copy_from_slice(&tmp);

                buf_tail = MACSIZE;
            }

            if input_length == 0 {
                break;
            }
        }
        Ok(hmac.verify(&buf[..MACSIZE]).is_ok())
    }
}
