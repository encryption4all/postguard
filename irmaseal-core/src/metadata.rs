use crate::{
    util::{derive_keys, generate_iv, KeySet},
    *,
};
use arrayref::array_ref;
use arrayvec::ArrayVec;
use core::convert::TryFrom;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub(crate) const KEYSIZE: usize = 32;
pub(crate) const IVSIZE: usize = 16;
#[allow(dead_code)]
pub(crate) const MACSIZE: usize = 32;
pub(crate) const CIPHERTEXT_SIZE: usize = 144;
pub(crate) const VERSION_V1: u16 = 0;

/// Metadata which contains the version
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Metadata {
    pub ciphertext: ArrayVec<[u8; CIPHERTEXT_SIZE]>,
    pub iv: ArrayVec<[u8; IVSIZE]>,
    pub identity: Identity,
}

pub struct MetadataCreateResult {
    pub header: HeaderBuf,
    pub metadata: Metadata,
    pub keys: KeySet,
}

impl Metadata {
    /// Conveniently construct a new Metadata. It is also possible to directly construct this object.
    ///
    /// Throws a ConstraintViolation when the type or value strings are too long..
    pub fn new<R: Rng + CryptoRng>(
        identity: Identity,
        pk: &PublicKey,
        rng: &mut R,
    ) -> Result<MetadataCreateResult, Error> {
        let version_buf = VERSION_V1.to_be_bytes();

        let derived = identity.derive()?;
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &derived, rng);

        let keys = derive_keys(&k);
        let iv = ArrayVec::try_from(generate_iv(rng)).unwrap();
        let ciphertext = ArrayVec::try_from(c.to_bytes()).unwrap();

        let metadata = Metadata {
            ciphertext,
            iv,
            identity,
        };
        let mut header = HeaderBuf::try_from([0; MAX_HEADERBUF_SIZE]).unwrap();

        let header_slice: &mut [u8] = header.as_mut_slice();

        let prelude_off_start = 0;
        let prelude_off_end = prelude_off_start + PRELUDE_SIZE;
        let version_off_start = prelude_off_end;
        let version_off_end = version_off_start + mem::size_of::<u16>();
        let meta_len_off_start = version_off_end;
        let meta_len_off_end = version_off_end + mem::size_of::<u32>();

        let meta_bytes = postcard::to_slice(&metadata, &mut header_slice[PREAMBLE_SIZE..])
            .or(Err(Error::ConstraintViolation))?;

        let metadata_len = meta_bytes.len();

        let metadata_len_buf = u32::try_from(metadata_len)
            .or(Err(Error::ConstraintViolation))?
            .to_be_bytes();

        header_slice[prelude_off_start..prelude_off_end].clone_from_slice(&PRELUDE);
        header_slice[version_off_start..version_off_end].clone_from_slice(&version_buf);
        header_slice[meta_len_off_start..meta_len_off_end].clone_from_slice(&metadata_len_buf);

        header.truncate(PREAMBLE_SIZE + metadata_len);

        Ok(MetadataCreateResult {
            header: header,
            metadata: metadata,
            keys: keys,
        })
    }

    pub fn derive_keys(self, usk: &UserSecretKey) -> Result<KeySet, Error> {
        let c = crate::util::open_ct(ibe::kiltz_vahlis_one::CipherText::from_bytes(array_ref!(
            self.ciphertext.as_slice(),
            0,
            CIPHERTEXT_SIZE
        )))
        .ok_or(Error::FormatViolation)?;

        let m = ibe::kiltz_vahlis_one::decrypt(&usk.0, &c);

        Ok(derive_keys(&m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_write_read() {
        let mut rng = rand::thread_rng();

        let i = Identity::new(
            1566722350,
            "pbdf.pbdf.email.email",
            Some("w.geraedts@sarif.nl"),
        )
        .unwrap();

        let (pk, sk) = ibe::kiltz_vahlis_one::setup(&mut rng);

        let MetadataCreateResult {
            metadata: m,
            header: h,
            keys: keys,
        } = Metadata::new(i.clone(), &PublicKey(pk.clone()), &mut rng).unwrap();

        let mut reader = MetadataReader::new();
        match reader.write(&h.as_slice()).unwrap() {
            MetadataReaderResult::Hungry => panic!("Unsaturated"),
            MetadataReaderResult::Saturated {
                unconsumed: u,
                header: h2,
                metadata: m2,
            } => panic!("Saturated"),
        }
    }
}
