use crate::artifacts::UserSecretKey;
use crate::*;
use crate::{Error, HiddenPolicy};
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::mr::{MultiRecipient, MultiRecipientCiphertext};
use ibe::kem::{SharedSecret, IBKEM};
use ibe::Compress;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Read;
use std::io::Write;

/// Possible encryption modes.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub enum Mode {
    /// The payload is a stream, processed in segments.
    Streaming {
        /// The size in which segments are processed and authenticated.
        segment_size: u32,

        /// Possible size hint about the payload in the form (min, max), defaults to (0, None).
        ///
        /// Can be used to allocate memory beforehand, saving re-allocations.
        size_hint: (u64, Option<u64>),
    },

    /// The payload is processed fully in memory, its size is known beforehand.
    InMemory { size: u32 },
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Streaming {
            segment_size: SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
            size_hint: (0, None),
        }
    }
}

/// Possible symmetric-key encryption algorithms.
// We only target 128-bit security because it more closely matches the security target BLS12-381.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub enum Algorithm {
    // Good performance with hardware acceleration.
    Aes128Gcm { iv: [u8; 16] },
    // The algorithms listed below are unsupported, but reserved for future use.
    // Good performance in software.
    XSalsa20Poly1305 { iv: [u8; 24] },
    // CAESAR finalist.
    Aes128Ocb { iv: [u8; 12] },
}

impl Algorithm {
    fn new_aes128_gcm<R: Rng + CryptoRng>(r: &mut R) -> Self {
        let mut iv = [0u8; 16];
        r.fill_bytes(&mut iv);

        Self::Aes128Gcm { iv }
    }
}

/// Header type, contains headerdata for _ALL_ recipients.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Header {
    /// Map of recipient identifiers to [`RecipientHeader`]s.
    #[serde(rename = "rs")]
    pub policies: BTreeMap<String, RecipientHeader>,

    /// The symmetric-key encryption algorithm used.
    pub algo: Algorithm,

    /// The encryption mode.
    #[serde(default)]
    pub mode: Mode,
}

/// Contains data specific to one recipient.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientHeader {
    /// The [`HiddenPolicy`] associated with this identifier.
    #[serde(rename = "p")]
    pub policy: HiddenPolicy,

    /// The serialized ciphertext for this specific recipient.
    #[serde(with = "BigArray")]
    pub ct: [u8; MultiRecipientCiphertext::<CGWKV>::OUTPUT_SIZE],
}

impl RecipientHeader {
    /// Decapsulates a [`ibe::kem::SharedSecret`] from a [`RecipientHeader`].
    ///
    /// These bytes can either directly be used for an AEAD, or a key derivation function.
    pub fn derive_keys(&self, usk: &UserSecretKey<CGWKV>) -> Result<SharedSecret, Error> {
        let c = crate::util::open_ct(MultiRecipientCiphertext::<CGWKV>::from_bytes(&self.ct))
            .ok_or(Error::FormatViolation)?;

        CGWKV::multi_decaps(None, &usk.0, &c).map_err(Error::Kem)
    }
}

impl Header {
    /// Creates a new [`Header`] using the Master Public Key and the policies.
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

        // Generate all RecipientHeader's.
        let recipient_info: BTreeMap<String, RecipientHeader> = policies
            .iter()
            .zip(cts.iter())
            .map(|((rid, policy), ct)| {
                (
                    rid.clone(),
                    RecipientHeader {
                        policy: policy.to_hidden(),
                        ct: ct.to_bytes(),
                    },
                )
            })
            .collect();

        Ok((
            Header {
                policies: recipient_info,
                algo: Algorithm::new_aes128_gcm(rng),
                mode: Mode::default(),
            },
            ss,
        ))
    }

    /// Set the encryption mode.
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the encryption algorithm.
    pub fn with_algo(mut self, algo: Algorithm) -> Self {
        self.algo = algo;
        self
    }

    /// Serializes the [`Header`] as compact binary MessagePack format into a [`std::io::Write`].
    ///
    /// Internally uses the "named" convention, which preserves field names.
    /// Fields names are shortened to limit overhead:
    /// * `rs`: map of serialized [`RecipientHeader`]s with keyed by recipient identifier,
    ///    * `p`: serialized [`HiddenPolicy`],
    ///    * `ct`: associated ciphertext with this policy,
    /// * `algo`: [algorithm][`Algorithm`],
    /// * `mode`: [mode][`Mode`],
    /// * `iv`: 32-byte initialization vector.
    pub fn msgpack_into<W: Write>(self, w: &mut W) -> Result<(), Error> {
        let mut serializer = rmp_serde::encode::Serializer::new(w)
            .with_struct_map()
            .with_string_variants();

        self.serialize(&mut serializer)
            .map_err(|_e| Error::ConstraintViolation)
    }

    /// Deserialize the headerdata from binary MessagePack format.
    pub fn msgpack_from<R: Read>(r: R) -> Result<Self, Error> {
        rmp_serde::decode::from_read(r).map_err(|_| Error::FormatViolation)
    }

    /// Serializes the headerdata to a JSON string.
    ///
    /// Should only be used for small headerdata or development purposes,
    /// or when compactness is not required.
    pub fn to_json_string(self) -> Result<String, Error> {
        serde_json::to_string(&self).or(Err(Error::FormatViolation))
    }

    /// Deserialize the headerdata from a JSON string.
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
        let (header, _ss) = Header::new(&setup.mpk, &setup.policies, &mut rng).unwrap();
        let header2 = header.clone();

        let s = header.to_json_string().unwrap();
        let decoded = Header::from_json_string(&s).unwrap();

        assert_eq!(decoded.policies.len(), 2);
        assert_eq!(
            &decoded.policies.get(&ids[0]).unwrap().policy,
            &setup.policies.get(&ids[0]).unwrap().to_hidden()
        );

        assert_eq!(&decoded.algo, &header2.algo);
        assert_eq!(&decoded.mode, &header2.mode);
    }

    #[test]
    fn test_enc_dec_msgpack() {
        use std::io::Cursor;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();
        let ids: Vec<String> = setup.policies.keys().cloned().collect();

        let (header, _ss) = Header::new(&setup.mpk, &setup.policies, &mut rng).unwrap();
        let header2 = header.clone();

        let mut v = Vec::new();
        header.msgpack_into(&mut v).unwrap();

        let decoded = Header::msgpack_from(Cursor::new(v)).unwrap();

        assert_eq!(decoded.policies.len(), 2);
        assert_eq!(
            &decoded.policies.get(&ids[0]).unwrap().policy,
            &setup.policies.get(&ids[0]).unwrap().to_hidden()
        );
        assert_eq!(&decoded.algo, &header2.algo);
        assert_eq!(&decoded.mode, &header2.mode);
    }

    #[test]
    fn test_transcode() {
        // This test encodes to binary and then transcodes into serde_json.
        // The transcoded data is compared with a direct serialization of the same header.
        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();

        let mut v1 = Vec::new();

        let header = Header::new(&setup.mpk, &setup.policies, &mut rng)
            .unwrap()
            .0
            .with_mode(Mode::InMemory { size: 1024 })
            .with_algo(Algorithm::new_aes128_gcm(&mut rng));

        let header2 = header.clone();

        header.msgpack_into(&mut v1).unwrap();

        let s1 = header2.to_json_string().unwrap();

        let mut tmp = Vec::new();

        {
            let mut des = rmp_serde::decode::Deserializer::new(&v1[..]);
            let mut ser = serde_json::Serializer::new(&mut tmp);
            serde_transcode::transcode(&mut des, &mut ser).unwrap();
        }

        let s2 = String::from_utf8(tmp).unwrap();

        assert_eq!(s1, s2);
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

        let (header, ss1) = Header::new(&setup.mpk, &setup.policies, &mut rng).unwrap();
        let header2 = header.clone();
        let header3 = header.clone();

        // Encode to binary via MessagePack.
        let mut v = Vec::new();
        header.msgpack_into(&mut v).unwrap();

        // Encode to JSON string.
        let json = header2.to_json_string().unwrap();

        let decoded1 = Header::msgpack_from(Cursor::new(v)).unwrap();
        let ss2 = decoded1
            .policies
            .get(test_id)
            .unwrap()
            .derive_keys(test_usk)
            .unwrap();

        let decoded2 = Header::from_json_string(&json).unwrap();
        let ss3 = decoded2
            .policies
            .get(test_id)
            .unwrap()
            .derive_keys(test_usk)
            .unwrap();

        assert_eq!(&decoded1.policies.len(), &header3.policies.len());
        assert_eq!(&decoded1.algo, &header3.algo);
        assert_eq!(&decoded1.mode, &header3.mode);

        // Make sure we derive the same keys.
        assert_eq!(&ss1, &ss2);
        assert_eq!(&ss1, &ss3);
    }
}
