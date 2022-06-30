use crate::artifacts::{MultiRecipientCiphertext, UserSecretKey};
use crate::util::generate_iv;
use crate::*;
use crate::{Error, HiddenPolicy, IV_SIZE};
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::mkem::MultiRecipient;
use ibe::kem::{SharedSecret, IBKEM};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Read;
use std::io::Write;

/// This struct containts metadata for _ALL_ recipients.
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "rs")]
    pub policies: BTreeMap<String, RecipientInfo>,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    #[serde(rename = "cs")]
    pub chunk_size: usize,
}

/// Contains data specific to one recipient.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientInfo {
    /// The hidden policy associated with this identifier.
    #[serde(rename = "p")]
    pub policy: HiddenPolicy,

    /// Ciphertext for this specific recipient.
    pub ct: MultiRecipientCiphertext<CGWKV>,
}

impl RecipientInfo {
    /// Derives a [`ibe::kem::SharedSecret`] from a [`RecipientInfo`].
    ///
    /// These bytes can either directly be used for an AEAD, or a key derivation function.
    pub fn derive_keys(&self, usk: &UserSecretKey<CGWKV>) -> Result<SharedSecret, Error> {
        CGWKV::multi_decaps(None, &usk.0, &self.ct.0).map_err(Error::Kem)
    }
}

impl Metadata {
    pub fn new<R: Rng + CryptoRng>(
        pk: &PublicKey<CGWKV>,
        policies: &BTreeMap<String, Policy>,
        rng: &mut R,
    ) -> Result<(Self, SharedSecret), Error> {
        // Map policies to IBE identities.
        let ids = policies
            .values()
            .map(|p| p.derive::<CGWKV>())
            .collect::<Result<Vec<<CGWKV as IBKEM>::Id>, _>>()?;

        // Generate the shared secret and ciphertexts.
        let (cts, ss) = CGWKV::multi_encaps(&pk.0, &ids[..], rng);

        // Generate all RecipientInfo's.
        let recipient_info: BTreeMap<String, RecipientInfo> = policies
            .iter()
            .zip(cts)
            .map(|((rid, policy), ct)| {
                (
                    rid.clone(),
                    RecipientInfo {
                        policy: policy.to_hidden(),
                        ct: MultiRecipientCiphertext(ct),
                    },
                )
            })
            .collect();

        let iv = generate_iv(rng);

        Ok((
            Metadata {
                policies: recipient_info,
                iv,
                chunk_size: SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
            },
            ss,
        ))
    }

    /// Writes binary MessagePack format into a [`std::io::Write`].
    ///
    /// Internally uses the "named" convention, which preserves field names.
    /// Fields names are shortened to limit overhead:
    /// `rs`: map of serialized `RecipientInfo`s with keyed by recipient identifier,
    ///     `p`: serialized `HiddenPolicy`,
    ///     `ct`: associated ciphertext with this policy,
    /// `iv`: 16-byte initialization vector,
    /// `cs`: chunk size in bytes used in the symmetrical encryption.
    pub fn msgpack_into<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        let mut serializer = rmp_serde::encode::Serializer::new(w).with_struct_map();

        self.serialize(&mut serializer)
            .map_err(|_e| Error::ConstraintViolation)
    }

    /// Deserialize the metadata from binary MessagePack format.
    pub fn msgpack_from<R: Read>(r: R) -> Result<Self, Error> {
        rmp_serde::decode::from_read(r).map_err(|_e| Error::FormatViolation)
    }

    /// Serializes the metadata to a json string.
    ///
    /// Should only be used for small metadata or development purposes,
    /// or when compactness is not required.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self).or(Err(Error::FormatViolation))
    }

    /// Deserialize the metadata from a json string.
    pub fn from_json_string(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(|_| Error::FormatViolation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_common::TestSetup;

    #[test]
    fn test_enc_dec_json() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();
        let ids: Vec<String> = setup.policies.keys().cloned().collect();

        let (meta, _ss) = Metadata::new(&setup.mpk, &setup.policies, &mut rng).unwrap();

        let s = meta.to_json_string().unwrap();

        let decoded = Metadata::from_json_string(&s).unwrap();

        assert_eq!(decoded.policies.len(), 2);

        assert_eq!(
            &decoded.policies.get(&ids[0]).unwrap().policy,
            &setup.policies.get(&ids[0]).unwrap().to_hidden()
        );

        assert_eq!(&decoded.iv, &meta.iv);
        assert_eq!(&decoded.chunk_size, &meta.chunk_size);
    }

    #[test]
    fn test_enc_dec_msgpack() {
        use std::io::Cursor;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();
        let ids: Vec<String> = setup.policies.keys().cloned().collect();

        let (meta, _ss) = Metadata::new(&setup.mpk, &setup.policies, &mut rng).unwrap();

        let mut v = Vec::new();
        meta.msgpack_into(&mut v).unwrap();

        let mut c = Cursor::new(v);
        let decoded = Metadata::msgpack_from(&mut c).unwrap();

        assert_eq!(
            &decoded.policies.get(&ids[0]).unwrap().policy,
            &setup.policies.get(&ids[0]).unwrap().to_hidden()
        );
        assert_eq!(&decoded.iv, &meta.iv);
        assert_eq!(&decoded.chunk_size, &meta.chunk_size);
    }

    #[test]
    fn test_transcode() {
        // This test encodes to binary and then transcodes into serde_json.
        // The transcoded data is compared with a direct serialization of the same metadata.
        use std::io::Cursor;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();

        let (meta, _ss) = Metadata::new(&setup.mpk, &setup.policies, &mut rng).unwrap();

        let mut binary = Vec::new();
        meta.msgpack_into(&mut binary).unwrap();

        let v1 = serde_json::to_vec(&meta).unwrap();
        let mut v2 = Vec::new();

        let mut des = rmp_serde::decode::Deserializer::new(&binary[..]);
        let mut ser = serde_json::Serializer::new(Cursor::new(&mut v2));

        serde_transcode::transcode(&mut des, &mut ser).unwrap();

        assert_eq!(&v1, &v2);
    }

    #[test]
    fn test_round() {
        // This test tests that both encoding methods derive the same keys as the sender.
        use std::io::Cursor;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();
        let ids: Vec<String> = setup.policies.keys().cloned().collect();

        let test_id = &ids[1];
        let test_usk = &setup.usks.get(test_id).unwrap();

        let (meta, ss1) = Metadata::new(&setup.mpk, &setup.policies, &mut rng).unwrap();
        // Encode to binary via MessagePack.
        let mut v = Vec::new();
        meta.msgpack_into(&mut v).unwrap();

        // Encode to JSON string.
        let s = meta.to_json_string().unwrap();

        let mut c = Cursor::new(v);
        let decoded1 = Metadata::msgpack_from(&mut c).unwrap();
        let ss2 = decoded1
            .policies
            .get(test_id)
            .unwrap()
            .derive_keys(test_usk)
            .unwrap();

        let decoded2 = Metadata::from_json_string(&s).unwrap();
        let ss3 = decoded2
            .policies
            .get(test_id)
            .unwrap()
            .derive_keys(test_usk)
            .unwrap();

        assert_eq!(&decoded1.iv, &meta.iv);
        assert_eq!(&decoded1.chunk_size, &meta.chunk_size);

        // Make sure we derive the same keys.
        assert_eq!(&ss1, &ss2);
        assert_eq!(&ss1, &ss3);
    }
}
