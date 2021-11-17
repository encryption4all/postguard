use std::convert::TryInto;

use crate::*;

use alloc::fmt;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::Deserialize;

impl RecipientMetadata {
    pub fn from_string<'a>(s: &'a str, id: &RecipientIdentifier) -> Result<Self, Error> {
        let mut deserializer = serde_json::Deserializer::from_str(s);
        Ok(Self::default_with_id(id)
            .deserialize(&mut deserializer)
            .map_err(|_| Error::FormatViolation)?)
    }

    /// Deserialize metadata byte stream for a specific identifier.
    pub fn msgpack_from<'a, R: std::io::Read>(
        mut r: R,
        id: &RecipientIdentifier,
    ) -> Result<Self, Error> {
        let mut tmp = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut tmp).map_err(|_e| Error::NotIRMASEAL)?;

        if tmp[..PRELUDE_SIZE] != PRELUDE {
            Err(Error::NotIRMASEAL)?
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            Err(Error::VersionError)?
        }

        let metadata_len = u32::from_be_bytes(
            tmp[PREAMBLE_SIZE - METADATA_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        // Limit the reader, otherwise it would read into possibly a payload
        let meta_reader = r.take(metadata_len as u64);

        let mut deserializer = rmp_serde::decode::Deserializer::new(meta_reader);
        Ok(Self::default_with_id(id)
            .deserialize(&mut deserializer)
            .map_err(|_e| Error::FormatViolation)?)
    }
}

struct PartialEqVisitor<T> {
    looking_for: T,
}

/// Visits any types that implements PartialEq and returns instance of type T once found.
impl<'de, T> Visitor<'de> for PartialEqVisitor<T>
where
    T: Deserialize<'de> + PartialEq + fmt::Debug,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut found: Option<T> = None;

        while let Some(el) = seq.next_element()? {
            if el == self.looking_for {
                found = Some(el);
                break;
            }
        }

        while let Some(IgnoredAny) = seq.next_element()? {}

        found.ok_or_else(|| serde::de::Error::custom("not found"))
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

// This looks like a lot of code, but it is almost identical to what Serde's macros generate.
impl<'de> DeserializeSeed<'de> for RecipientMetadata {
    type Value = Self;

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

        struct RecipientMetadataVisitor<RecipientMetadata>(RecipientMetadata);

        impl<'de> Visitor<'de> for RecipientMetadataVisitor<RecipientMetadata> {
            type Value = RecipientMetadata;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("metadata struct")
            }

            // Required when struct was serialized to sequence.
            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let recipient_info = seq
                    .next_element_seed(self.0.recipient_info)?
                    .ok_or_else(|| serde::de::Error::missing_field("recipient"))?;
                let iv = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::missing_field("iv"))?;
                let chunk_size = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::missing_field("chunk_size"))?;

                Ok(RecipientMetadata {
                    recipient_info,
                    iv,
                    chunk_size,
                })
            }

            // Required when struct was serialized to map.
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
                                Some(map.next_value_seed(self.0.recipient_info.clone())?);
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

                Ok(RecipientMetadata {
                    recipient_info,
                    iv,
                    chunk_size,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["rs", "iv", "cs"];
        deserializer.deserialize_struct("RecipientMetadata", FIELDS, RecipientMetadataVisitor(self))
    }
}
