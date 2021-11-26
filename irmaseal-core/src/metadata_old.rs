use crate::{
    util::{derive_keys, generate_iv, KeySet},
    *,
};
use core::convert::{TryFrom, TryInto};
use ibe::kem::cgw_fo::{CGWFO, CT_BYTES as CGWFO_CT_BYTES};
use ibe::{kem::IBKEM, Compress};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[cfg(feature = "v1")]
pub mod v1 {
    use super::*;
    use ibe::kem::kiltz_vahlis_one::{CT_BYTES as KV1_CT_BYTES, KV1};

    /// Legacy struct, make sure this stays identical.
    /// Otherwise newer client cannot handle IRMAseal encrypted messages from older clients.
    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    pub struct V1Metadata {
        pub ciphertext: ArrayVec<u8, KV1_CT_BYTES>,
        pub iv: ArrayVec<u8, IV_SIZE>,
        pub identity: Identity,
    }

    impl V1Metadata {
        pub fn derive_keys(&self, usk: &UserSecretKey<KV1>) -> Result<KeySet, Error> {
            let c = crate::util::open_ct(<KV1 as IBKEM>::Ct::from_bytes(
                &self.ciphertext.as_slice().try_into().unwrap(),
            ))
            .ok_or(Error::FormatViolation)?;
            let ss = KV1::decaps(None, &usk.0, &c).unwrap();

            Ok(derive_keys(&ss))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V2Metadata {
    /// The ciphertext of the shared secret.
    #[serde(with = "BigArray")]
    pub ct: [u8; CGWFO_CT_BYTES],

    /// The identity that was used to encapsulate the shared secret.
    /// TODO: replace this with a hint since it should be anonymous.
    pub identity: Identity,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    pub chunk_size: usize,
}

/// Metadata.
///
/// Contains everything needed to decrypt a payload encrypted using the IRMASeal.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Metadata {
    #[cfg(feature = "v1")]
    V1(v1::V1Metadata),
    V2(V2Metadata),
}

pub struct MetadataCreateResult {
    /// The raw metadata header. Useful as associated data in an AEAD scheme.
    pub header: HeaderBuf,
    pub metadata: Metadata,
    pub keys: KeySet,
}

impl Metadata {
    /// Construct a new metadata packet.
    /// This function always returns a metadata from the newest version.
    ///
    /// # Errors
    ///
    /// Throws a `ConstraintViolation` when the type or value are of incorrect form.
    pub fn new<R: Rng + CryptoRng>(
        id: Identity,
        pk: &PublicKey<CGWFO>,
        rng: &mut R,
    ) -> Result<MetadataCreateResult, Error> {
        let version_buf = VERSION_V2.to_be_bytes();

        let derived = id.derive::<CGWFO>()?;
        let (c, k) = CGWFO::encaps(&pk.0, &derived, rng);

        let ct = c.to_bytes().as_ref().try_into().unwrap();
        let iv = generate_iv(rng);

        let metadata = Metadata::V2(V2Metadata {
            ct,
            iv,
            identity: id,
            chunk_size: SYMMETRIC_CRYPTO_BLOCKSIZE,
        });

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

        let keys = derive_keys(&k);

        Ok(MetadataCreateResult {
            header,
            metadata,
            keys,
        })
    }
}

impl V2Metadata {
    /// Decapsulate and derive symmetric keys from a metadata.
    pub fn derive_keys(
        &self,
        usk: &UserSecretKey<CGWFO>,
        pk: &PublicKey<CGWFO>,
    ) -> Result<KeySet, Error> {
        let c = crate::util::open_ct(<CGWFO as IBKEM>::Ct::from_bytes(&self.ct))
            .ok_or(Error::FormatViolation)?;
        let ss = CGWFO::decaps(Some(&pk.0), &usk.0, &c).map_err(|_e| Error::DecapsulationError)?;

        Ok(derive_keys(&ss))
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

        let (pk, _) = CGWFO::setup(&mut rng);

        let MetadataCreateResult {
            metadata: m,
            header: h,
            keys: _,
        } = Metadata::new(i.clone(), &PublicKey(pk.clone()), &mut rng).unwrap();

        let mut reader = MetadataReader::new();
        match reader.write(&h.as_slice()).unwrap() {
            MetadataReaderResult::Hungry => panic!("Should not be hungry"),
            MetadataReaderResult::Saturated {
                unconsumed: u,
                header: h2,
                metadata: m2,
                version: v2,
            } => {
                assert_eq!(u, 0);
                assert_eq!(&h, &h2);
                assert_eq!(&m, &m2);
                assert_eq!(&VERSION_V2, &v2);
            }
        }
    }
}
