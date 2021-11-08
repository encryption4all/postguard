use crate::{
    util::{derive_keys, generate_iv, KeySet},
    *,
};
use alloc::fmt;
use alloc::fmt::Debug;
use arrayvec::ArrayString;
use bincode::Options;
//use ibe::kem::cgw_fo::{CGWFO, CT_BYTES as CGWFO_CT_BYTES};
//use ibe::{kem::IBKEM, Compress};

use serde::de::{DeserializeSeed, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use serde_with::base64::Base64;
use serde_with::serde_as;
use std::io::Write as StdWrite;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecipientIdentifier(pub ArrayString<255>);

impl RecipientIdentifier {
    pub fn new<'a>(s: &'a str) -> Self {
        let mut new = ArrayString::<255>::new();
        new.push_str(s);
        Self(new)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct RecipientInfo {
    /// Identifier
    identifier: RecipientIdentifier,

    /// TODO: replace this with a hint since it should be anonymous.
    policy: Identity,

    /// Ciphertext for this specifiek recipient
    //    #[serde_as(as = "Base64")]
    #[serde(with = "BigArray")]
    ct: [u8; 5],
}

impl PartialEq for RecipientInfo {
    fn eq(&self, other: &Self) -> bool {
        self.identifier == other.identifier
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Metadata {
    /// The identity and associated ciphertext as a tuple.
    pub recipient_info: RecipientInfo,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    pub chunk_size: usize,
}

struct PartialEqVisitor<T> {
    looking_for: T,
}

/// Visits any types that implements PartialEq and returns instance of type T once found.
impl<'de, T> Visitor<'de> for PartialEqVisitor<T>
where
    T: Deserialize<'de> + PartialEq,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        loop {
            match seq.next_element::<T>() {
                Ok(Some(el)) => {
                    if el == self.looking_for {
                        break Ok(el);
                    }
                }
                Ok(None) => break Err(serde::de::Error::custom("not found")),
                Err(_) => break Err(serde::de::Error::custom("unexpected error")),
            }
        }
    }
}

impl<'de> DeserializeSeed<'de> for RecipientInfo {
    type Value = Self;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let recipient_info = deserializer
            .deserialize_seq(PartialEqVisitor::<RecipientInfo> { looking_for: self })?;

        Ok(recipient_info)
    }
}

impl<'de> DeserializeSeed<'de> for Metadata {
    type Value = Self;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            #[serde(rename = "recipients")]
            RecipientInfo,
            #[serde(rename = "iv")]
            Iv,
            #[serde(rename = "chunk_size")]
            ChunkSize,
        }

        struct MetadataVisitor<Metadata>(Metadata);

        impl<'de> Visitor<'de> for MetadataVisitor<Metadata> {
            type Value = Metadata;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("metadata struct")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let recipient_info = seq
                    .next_element_seed(self.0.recipient_info)?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let iv = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let chunk_size = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                Ok(Metadata {
                    recipient_info,
                    iv,
                    chunk_size,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut recipient_info = None;
                let mut iv = None;
                let mut chunk_size = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::RecipientInfo => {
                            if recipient_info.is_some() {
                                return Err(serde::de::Error::duplicate_field("recipient_info"));
                            }
                            recipient_info = Some(map.next_value_seed(self.0.recipient_info)?);
                        }
                        Field::Iv => {
                            if iv.is_some() {
                                return Err(serde::de::Error::duplicate_field("iv"));
                            }
                            iv = Some(map.next_value()?);
                        }
                        Field::ChunkSize => {
                            if chunk_size.is_some() {
                                return Err(serde::de::Error::duplicate_field("chunk_size"));
                            }
                            chunk_size = Some(map.next_value()?);
                        }
                    }
                }

                let recipient_info = recipient_info
                    .ok_or_else(|| serde::de::Error::missing_field("recipient_info"))?;
                let iv = iv.ok_or_else(|| serde::de::Error::missing_field("iv"))?;
                let chunk_size =
                    chunk_size.ok_or_else(|| serde::de::Error::missing_field("chunk_size"))?;

                Ok(Metadata {
                    recipient_info,
                    iv,
                    chunk_size,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["recipients", "iv", "chunk_size"];
        deserializer.deserialize_struct("Metadata", FIELDS, MetadataVisitor(self))
    }
}

impl Metadata {
    // /// Derive keys
    //    pub fn derive_keys(
    //        &self,
    //        usk: &UserSecretKey<CGWFO>,
    //        pk: &PublicKey<CGWFO>,
    //    ) -> Result<KeySet, Error> {

    fn default_with_id(id: &RecipientIdentifier) -> Self {
        Self {
            recipient_info: RecipientInfo {
                identifier: id.clone(),
                policy: Identity::default(),
                ct: [0u8; 5],
            },
            iv: [0u8; IV_SIZE],
            chunk_size: 0 as usize,
        }
    }

    // TODO: all 4 functions
    // - serde_json:
    //  - from_string
    //  - from_reader
    // - bincode:
    //  - from_slice
    //  - from_reader

    pub fn from_slice<'a>(data: &'a [u8], id: &RecipientIdentifier) -> Result<Self, Error> {
        Ok(bincode::config::DefaultOptions::new()
            .deserialize_seed(Self::default_with_id(id), data)
            .or(Err(Error::FormatViolation)))?
    }

    pub fn from_string<'a>(s: &'a str, id: &RecipientIdentifier) -> Result<Self, Error> {
        let mut deserializer = serde_json::Deserializer::from_str(s);
        Ok(Self::default_with_id(id)
            .deserialize(&mut deserializer)
            .or(Err(Error::FormatViolation)))?
    }
}

// TODO: make this a map?
#[derive(Clone)]
pub struct RecipientPolicyList<'a>(&'a [(&'a RecipientIdentifier, &'a Identity)]);

/// Serializes encapsulation of a shared secret for each Identifier/Identiy combination serialization.
fn serialize_encaps<S>(list: &RecipientPolicyList, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    //    let mut map = serializer.serialize_map(Some(list.0.len()))?;
    //    for (id, policy) in list.0 {
    //        let ct = [7u8; 5];
    //
    //        let recipient_info = RecipientInfo {
    //            identifier: *id.clone(),
    //            policy: *policy.clone(),
    //            ct,
    //        };
    //
    //        map.serialize_entry(id, &recipient_info)?;
    //    }
    //
    //    map.end()

    let mut seq = serializer.serialize_seq(Some(list.0.len()))?;
    for (id, policy) in list.0.into_iter() {
        // TODO: make a real ciphertext for the policy using IBE
        let ct = [7u8; 5];

        let recipient_info = RecipientInfo {
            identifier: *id.clone(),
            policy: *policy.clone(),
            ct,
        };

        seq.serialize_element(&recipient_info)?;
    }

    seq.end()
}

//fn serialize_bytes<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
//where
//    S: serde::Serializer,
//{
//    if serializer.is_human_readable() {
//        // base64ct
//        let mut enc_buf = [0u8; 128];
//        let encoded = Base64::encode(v, &mut enc_buf).unwrap();
//        serializer.serialize_str(encoded)
//    } else {
//        v.serialize(serializer)
//    }
//}

/// Can be serialized to a output format (json, bincode)
#[serde_as]
#[derive(Serialize, Clone)]
pub struct MetadataArguments<'a> {
    #[serde(serialize_with = "serialize_encaps")]
    recipients: RecipientPolicyList<'a>,
    //    #[serde(serialize_with = "serialize_bytes")]
    //    #[serde_as(as = "Base64")]
    iv: [u8; IV_SIZE],
    chunk_size: usize,
}

impl<'a> MetadataArguments<'a> {
    pub fn write_into<W: StdWrite>(&self, w: &mut W) -> Result<(), Error> {
        Ok(bincode::config::DefaultOptions::new()
            .serialize_into(w, self)
            .or(Err(Error::FormatViolation)))?
    }

    pub fn write_to_json_string(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(&self).or(Err(Error::FormatViolation)))?
    }

    // TODO: 4 functions
    // - serde_json:
    //  - to_string
    //  - to_writer
    // - bincode:
    //  - to_slice
    //  - to_writer
}

#[cfg(test)]
mod tests {
    macro_rules! setup {
        ($ma: ident) => {
            use super::*;

            // some inputs
            let mut rng = rand::thread_rng();
            let identifier1 = RecipientIdentifier::new("l.botros@cs.ru.nl");
            let identifier2 = RecipientIdentifier::new("leon.botros@gmail.com");

            let i1 = Identity::new(
                1566722350,
                "pbdf.pbdf.email.email",
                Some("l.botros@cs.ru.nl"),
            )
            .unwrap();

            let i2 = Identity::new(
                1566722350,
                "pbdf.pbdf.email.email",
                Some("leon.botros@gmail.com"),
            )
            .unwrap();

            let list = [(&identifier1, &i1), (&identifier2, &i2)];
            let c = RecipientPolicyList(&list);
            let iv = generate_iv(&mut rng);

            let $ma = MetadataArguments {
                recipients: c,
                iv,
                chunk_size: 1024 * 1024,
            };
        };
    }

    #[test]
    fn test_enc_dec_json() {
        setup!(ma);
        let id2 = &ma.recipients.0[1].0.clone();
        let policy2 = &ma.recipients.0[1].1.clone();

        let s = ma.write_to_json_string().unwrap();
        println!("{}", s);

        // decode string, while looking for identifier2
        let decoded = super::Metadata::from_string(&s, id2).unwrap();
        dbg!(&decoded);

        assert_eq!(&decoded.recipient_info.identifier, id2);
        assert_eq!(&decoded.recipient_info.policy, policy2);
        assert_eq!(&decoded.iv, &ma.iv);
        assert_eq!(&decoded.chunk_size, &ma.chunk_size);
    }

    #[test]
    fn test_enc_dec_bincode() {
        use std::io::Cursor;
        use std::io::Read;
        use std::io::{Seek, SeekFrom};

        /// Should work: deserialize to a full metadata struct with derived deserialization
        #[derive(Deserialize, Debug)]
        pub struct MetadataFull {
            /// The identity and associated ciphertext as a tuple.
            pub recipients: Vec<RecipientInfo>,

            /// The initializion vector used for symmetric encryption.
            pub iv: [u8; IV_SIZE],

            /// The size of the chunks in which to process symmetric encryption.
            pub chunk_size: usize,
        }

        setup!(ma);
        let id2 = &ma.recipients.0[1].0.clone();
        let policy2 = &ma.recipients.0[1].1.clone();

        let mut c: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        ma.write_into(&mut c).unwrap();
        dbg!(&c);

        let mut out = Vec::<u8>::new();
        c.seek(SeekFrom::Start(0)).unwrap();
        c.read_to_end(&mut out).unwrap();
        let decoded = super::Metadata::from_slice(out.as_slice(), &id2).unwrap();
        //dbg!(&decoded);

        let metafull: MetadataFull = bincode::config::DefaultOptions::new()
            .deserialize(out.as_slice())
            .unwrap();

        dbg!(&metafull);

        assert_eq!(&decoded.recipient_info.identifier, id2);
        assert_eq!(&decoded.recipient_info.policy, policy2);
        assert_eq!(&decoded.iv, &ma.iv);
        assert_eq!(&decoded.chunk_size, &ma.chunk_size);
    }

    #[test]
    fn test_transcode() {
        use serde_transcode::transcode;
        use std::io::Cursor;
        use std::io::Read;
        use std::io::{Seek, SeekFrom};

        setup!(ma);

        // encode to binary and transcode into json

        let mut c: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        ma.write_into(&mut c).unwrap();

        c.seek(SeekFrom::Start(0)).unwrap();

        let mut des =
            bincode::de::Deserializer::with_reader(&mut c, bincode::DefaultOptions::new());
        let mut ser = serde_json::Serializer::pretty(std::io::stdout());

        serde_transcode::transcode(&mut des, &mut ser).unwrap();
    }
}
