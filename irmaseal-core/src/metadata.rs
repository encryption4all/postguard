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
        let iv = generate_iv(rng)
            .iter()
            .cloned()
            .collect::<ArrayVec<[u8; IVSIZE]>>();

        let ciphertext = c
            .to_bytes()
            .iter()
            .cloned()
            .collect::<ArrayVec<[u8; CIPHERTEXT_SIZE]>>();

        let metadata = Metadata {
            ciphertext,
            iv,
            identity,
        };
        let mut header = HeaderBuf::new();
        let header_slice: &mut [u8] = header.as_mut_slice();

        let prelude_off_start = 0;
        let prelude_off_end = prelude_off_start + PRELUDE_LEN;
        let version_off_start = prelude_off_end;
        let version_off_end = version_off_start + mem::size_of::<u16>();
        let meta_len_off_start = version_off_end;
        let meta_len_off_end = version_off_end + mem::size_of::<u32>();

        let meta_bytes = postcard::to_slice(&metadata, &mut header_slice[PREAMBLE_SIZE..])
            .or(Err(Error::FormatViolation))?;

        let metadata_len = u32::try_from(meta_bytes.len())
            .or(Err(Error::FormatViolation))?
            .to_be_bytes();

        header_slice[prelude_off_start..prelude_off_end].clone_from_slice(&PRELUDE);
        header_slice[version_off_start..version_off_end].clone_from_slice(&version_buf);
        header_slice[meta_len_off_start..meta_len_off_end].clone_from_slice(&metadata_len);

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
