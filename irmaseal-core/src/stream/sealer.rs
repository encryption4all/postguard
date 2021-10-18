use ctr::cipher::{NewCipher, StreamCipher};
use digest::Digest;
use rand::{CryptoRng, Rng};

use crate::*;
use crate::{stream::*, util::KeySet};
use ibe::kem::cgw_fo::CGWFO;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, W: Writable> {
    encrypter: SymCrypt,
    mac: Mac,
    w: &'a mut W,
}

impl<'a, W: Writable> Sealer<'a, W> {
    pub fn new<R: Rng + CryptoRng>(
        i: Identity,
        pk: &PublicKey<CGWFO>,
        rng: &mut R,
        w: &'a mut W,
    ) -> Result<Sealer<'a, W>, Error> {
        let MetadataCreateResult {
            metadata: m,
            header: h,
            keys: KeySet { aes_key, mac_key },
        } = Metadata::new(i, pk, rng)?;
        if let Metadata::V2(x) = m {
            let encrypter = SymCrypt::new(&aes_key.into(), &x.iv.into());
            let mut mac = Mac::default();
            mac.input(&mac_key);
            mac.input(&h);
            w.write(&h).map_err(|_| Error::ConstraintViolation)?;

            Ok(Sealer { encrypter, mac, w })
        } else {
            Err(Error::ConstraintViolation)
        }
    }
}

impl Writable for Mac {
    fn write(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        self.input(buf);
        Ok(())
    }
}

impl<'a, W: Writable> Writable for Sealer<'a, W> {
    fn write(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        let mut tmp = [0u8; MAC_SIZE];

        for c in buf.chunks(MAC_SIZE) {
            let subtmp = &mut tmp[0..c.len()];
            subtmp.copy_from_slice(c);
            self.encrypter.apply_keystream(subtmp);
            self.mac.input(&subtmp);
            self.w.write(subtmp)?;
        }

        Ok(())
    }
}

impl<'a, W: Writable> Drop for Sealer<'a, W> {
    fn drop(&mut self) {
        let code = self.mac.result_reset();
        self.w.write(&code).unwrap()
    }
}
