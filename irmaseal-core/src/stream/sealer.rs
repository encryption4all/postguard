use ctr::stream_cipher::{NewStreamCipher, StreamCipher};
use hmac::Mac;
use rand::{CryptoRng, Rng};
use core::convert::TryFrom;

use crate::stream::*;
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, W: Writable> {
    aes: SymCrypt,
    hmac: Verifier,
    w: &'a mut W,
}

impl<'a, W: Writable> Sealer<'a, W> {
    pub fn new<R: Rng + CryptoRng>(
        media_type: &str,
        media_metadata: serde_json::Value,
        i: Identity,
        pk: &PublicKey,
        rng: &mut R,
        w: &'a mut W,
    ) -> Result<Sealer<'a, W>, Error> {
        let derived = i.derive()?;
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &derived, rng);

        let (aeskey, mackey) = crate::stream::util::derive_keys(&k);
        let iv = crate::stream::util::generate_iv(rng);

        let aes = SymCrypt::new(&aeskey.into(), &iv.into());
        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let ciphertext = c.to_bytes();

        let metadata = Metadata::new(Version::V1_0, media_type, media_metadata, &ciphertext, &iv, i)?;
        let json_bytes = serde_json::to_vec(&metadata).or(Err(Error::FormatViolation))?;

        let metadata_len = u16::try_from(json_bytes.len())
            .or(Err(Error::FormatViolation))?.to_be_bytes();

        hmac.write(&PRELUDE)?;
        w.write(&PRELUDE)?;

        hmac.write(&metadata_len)?;
        w.write(&metadata_len)?;

        hmac.write(&json_bytes.as_slice())?;
        w.write(json_bytes.as_slice())?;

        Ok(Sealer { aes, hmac, w })
    }
}

impl Writable for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.input(buf);
        Ok(())
    }
}

impl<'a, W: Writable> Writable for Sealer<'a, W> {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        let mut tmp = [0u8; BLOCKSIZE];

        for c in buf.chunks(BLOCKSIZE) {
            let subtmp = &mut tmp[0..c.len()];
            subtmp.copy_from_slice(c);
            self.aes.encrypt(subtmp);
            self.hmac.input(subtmp);
            self.w.write(subtmp)?;
        }

        Ok(())
    }
}

impl<'a, W: Writable> Drop for Sealer<'a, W> {
    fn drop(&mut self) {
        let code = self.hmac.result_reset().code();
        self.w.write(&code).unwrap()
    }
}
