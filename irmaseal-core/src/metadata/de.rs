use crate::*;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::Deserialize;
use std::convert::TryInto;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;

impl RecipientMetadata {
    pub fn from_string<'a>(s: &'a str, id: &str) -> Result<Self, Error> {
        let mut deserializer = serde_json::Deserializer::from_str(s);
        Ok(Seed::<RecipientMetadata>::new(id)
            .deserialize(&mut deserializer)
            .map_err(|_| Error::FormatViolation)?)
    }

    /// Deserialize metadata byte stream for a specific recipient identifier.
    pub fn msgpack_from<'a, R: Read>(mut r: R, id: &str) -> Result<Self, Error> {
        let mut tmp = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut tmp).map_err(|_e| Error::NotIRMASEAL)?;

        if tmp[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion);
        }

        let metadata_len = u32::from_be_bytes(
            tmp[PREAMBLE_SIZE - METADATA_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        // Limit the reader, otherwise it would read into possibly a payload
        let meta_reader = r.take(metadata_len as u64);

        let mut deserializer = rmp_serde::decode::Deserializer::new(meta_reader);
        Ok(Seed::<RecipientMetadata>::new(id)
            .deserialize(&mut deserializer)
            .map_err(|_e| Error::FormatViolation)?)
    }
}

struct KeyVisitor<K, V> {
    key: K,
    marker: PhantomData<fn(K) -> V>,
}

impl<K, V> KeyVisitor<K, V> {
    fn new(key: K) -> Self {
        Self {
            key,
            marker: PhantomData,
        }
    }
}

impl<'de, K, V> Visitor<'de> for KeyVisitor<K, V>
where
    V: Deserialize<'de>,
    K: Deserialize<'de> + PartialEq + Eq,
{
    type Value = V;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut found: Option<V> = None;

        while let Some((key, value)) = map.next_entry::<K, V>()? {
            if key == self.key {
                found = Some(value);
                break;
            }
        }

        while let Some((IgnoredAny, IgnoredAny)) = map.next_entry()? {}
        found.ok_or(serde::de::Error::custom("not found"))
    }
}

struct Seed<T> {
    id: String,
    marker: PhantomData<T>,
}

impl<T> Seed<T> {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            marker: PhantomData,
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seed<RecipientInfo> {
    type Value = RecipientInfo;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(KeyVisitor::<String, RecipientInfo>::new(self.id))
    }
}

impl<'de> DeserializeSeed<'de> for Seed<RecipientMetadata> {
    type Value = RecipientMetadata;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            #[serde(rename = "rs")]
            RecipientInfo,
            #[serde(rename = "iv")]
            Iv,
            #[serde(rename = "cs")]
            ChunkSize,
        }

        struct RecipientMetadataVisitor(String);

        impl<'de> Visitor<'de> for RecipientMetadataVisitor {
            type Value = RecipientMetadata;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("metadata struct")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let recipient_info = seq
                    .next_element_seed(Seed::<RecipientInfo>::new(&self.0))?
                    .ok_or(serde::de::Error::missing_field("recipient"))?;
                let iv = seq
                    .next_element()?
                    .ok_or(serde::de::Error::missing_field("iv"))?;
                let chunk_size = seq
                    .next_element()?
                    .ok_or(serde::de::Error::missing_field("chunk_size"))?;

                Ok(RecipientMetadata {
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
                            recipient_info =
                                Some(map.next_value_seed(Seed::<RecipientInfo>::new(&self.0))?);
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

                let recipient_info =
                    recipient_info.ok_or(serde::de::Error::missing_field("recipient_info"))?;
                let iv = iv.ok_or(serde::de::Error::missing_field("iv"))?;
                let chunk_size = chunk_size.ok_or(serde::de::Error::missing_field("chunk_size"))?;

                Ok(RecipientMetadata {
                    recipient_info,
                    iv,
                    chunk_size,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["rs", "iv", "cs"];
        deserializer.deserialize_struct(
            "RecipientMetadata",
            FIELDS,
            RecipientMetadataVisitor(self.id),
        )
    }
}
