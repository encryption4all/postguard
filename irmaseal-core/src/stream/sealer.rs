use arrayref::array_ref;
use ctr::stream_cipher::{NewStreamCipher, StreamCipher};
use digest::Digest;
use rand::{CryptoRng, Rng};

use crate::{stream::*, util::KeySet};
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, W: Writable> {
    encrypter: SymCrypt,
    verifier: Verifier,
    w: &'a mut W,
}

impl<'a, W: Writable> Sealer<'a, W> {
    pub fn new<R: Rng + CryptoRng>(
        i: Identity,
        pk: &PublicKey,
        rng: &mut R,
        w: &'a mut W,
    ) -> Result<Sealer<'a, W>, Error> {
        let MetadataCreateResult {
            metadata: m,
            header: h,
            keys: KeySet {
                aes_key,
                mac_key
            },
        } = Metadata::new(i, pk, rng)?;

        let iv: &[u8; IVSIZE] = array_ref!(m.iv.as_slice(), 0, IVSIZE);

        let encrypter = SymCrypt::new(&aes_key.into(), &(*iv).into());
        let mut verifier = Verifier::default();
        verifier.input(&mac_key);
        verifier.input(&h);

        Ok(Sealer {
            encrypter,
            verifier,
            w
        })
    }
}

impl Writable for Verifier {
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
            self.encrypter.encrypt(subtmp);
            self.verifier.input(&subtmp);
            self.w.write(subtmp)?;
        }

        Ok(())
    }
}

impl<'a, W: Writable> Drop for Sealer<'a, W> {
    fn drop(&mut self) {
        let code = self.verifier.result_reset();
        self.w.write(&code).unwrap()
    }
}
