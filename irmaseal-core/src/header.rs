//! IRMAseal encryption header definitions.

use crate::artifacts::{deserialize_bin_or_b64, serialize_bin_or_b64};
use crate::artifacts::{MultiRecipientCiphertext, PublicKey, UserSecretKey};
use crate::consts::*;
use crate::error::Error;
use crate::identity::{HiddenPolicy, Policy};
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::mkem::MultiRecipient;
use ibe::kem::{SharedSecret, IBKEM};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::{Read, Write};

/// Possible encryption modes.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
pub enum Mode {
    /// The payload is a stream, processed in segments.
    Streaming {
        /// The size of segments.
        segment_size: u32,

        /// Possible size hint about the payload in the form (min, max), defaults to (0, None).
        ///
        /// Can be used to allocate memory beforehand, saving re-allocations.
        size_hint: (u64, Option<u64>),
    },

    /// The payload is processed fully in memory, its size is known beforehand.
    InMemory {
        /// The size of the payload.
        size: u32,
    },
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Streaming {
            segment_size: SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
            size_hint: (0, None),
        }
    }
}

/// An initialization vector (IV).
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Iv<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> Iv<N> {
    fn random<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        let mut buf = [0u8; N];
        r.fill_bytes(&mut buf);
        Self(buf)
    }
}

// The IV is not secret but we do want to have the possibility to encode it as human-readable.
impl<const N: usize> Serialize for Iv<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_bin_or_b64(&self.0, serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Iv<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buf = [0u8; N];
        deserialize_bin_or_b64(&mut buf, deserializer)?;

        Ok(Self(buf))
    }
}

/// Supported symmetric-key encryption algorithms.
// We only target 128-bit security because it more closely matches the security target BLS12-381.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
pub enum Algorithm {
    /// AES-128-GCM.
    // Good performance with hardware acceleration.
    Aes128Gcm(Iv<12>),
    // The algorithms listed below are unsupported, but reserved for future use.
    /// XSalsa20Poly1305.
    // Good performance in software.
    XSalsa20Poly1305(Iv<24>),
    /// AES-128-OCB.
    // CAESAR finalist.
    Aes128Ocb(Iv<12>),
}

impl Algorithm {
    fn new_aes128_gcm<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        Self::Aes128Gcm(Iv::random(r))
    }
}

/// Header type, contains header for _all_ recipients.
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

    /// Ciphertext for this specific recipient.
    pub ct: MultiRecipientCiphertext<CGWKV>,
}

impl RecipientHeader {
    /// Decapsulates a [`ibe::kem::SharedSecret`] from a [`RecipientHeader`].
    ///
    /// These bytes can either directly be used for an AEAD, or a key derivation function.
    pub fn derive_keys(&self, usk: &UserSecretKey<CGWKV>) -> Result<SharedSecret, Error> {
        CGWKV::multi_decaps(None, &usk.0, &self.ct.0).map_err(|_e| Error::KEM)
    }
}

impl Header {
    /// Creates a new [`Header`] using the Master Public Key and the policies.
    pub fn new<R: RngCore + CryptoRng>(
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

        // Generate all RecipientHeaders.
        let recipient_info: BTreeMap<String, RecipientHeader> = policies
            .iter()
            .zip(cts)
            .map(|((rid, policy), ct)| {
                (
                    rid.clone(),
                    RecipientHeader {
                        policy: policy.to_hidden(),
                        ct: MultiRecipientCiphertext(ct),
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
    /// * `iv`: the initialization vector.
    pub fn msgpack_into<W: Write>(self, w: &mut W) -> Result<(), Error> {
        let mut serializer = rmp_serde::encode::Serializer::new(w);

        self.serialize(&mut serializer)
            .map_err(|e| Error::MessagePack(Box::new(e)))
    }

    /// Deserialize the header from binary MessagePack format.
    pub fn msgpack_from<R: Read>(r: R) -> Result<Self, Error> {
        rmp_serde::decode::from_read(r).map_err(|e| Error::MessagePack(Box::new(e)))
    }

    /// Serializes the header to a JSON string.
    ///
    /// Should only be used for small header or development purposes,
    /// or when compactness is not required.
    pub fn to_json_string(self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(Error::Json)
    }

    /// Deserialize the header from a JSON string.
    pub fn from_json_string(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(Error::Json)
    }

    //pub fn mode_checked(&self, expected: Mode) -> Result<Mode, Error> {}
    //pub fn algo_checked(&self, expected: Algorithm) -> Result<Algorithm, Error> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestSetup;

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
    #[should_panic]
    // NOTE: This test panics (for now), but it is a nice to have to support one day.
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
