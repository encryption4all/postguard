use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::str::FromStr;

/// String that can be displayed in multiple languages
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TranslatedString {
    pub en: String,
    pub nl: String,
}

// Utility for deserializing hashmaps with integers keys properly when coming from json
// Original deserializer suggested by Dtolnay in https://github.com/serde-rs/json/issues/560
// Can be removed once the underlying issue in serde/serde_json is fixed.
pub fn de_int_key<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Eq + Hash + FromStr,
    K::Err: Display,
    V: Deserialize<'de>,
{
    struct KeySeed<K> {
        k: PhantomData<K>,
    }

    impl<'de, K> DeserializeSeed<'de> for KeySeed<K>
    where
        K: FromStr,
        K::Err: Display,
    {
        type Value = K;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(self)
        }
    }

    impl<'de, K> Visitor<'de> for KeySeed<K>
    where
        K: FromStr,
        K::Err: Display,
    {
        type Value = K;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E>(self, string: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            K::from_str(string).map_err(de::Error::custom)
        }
    }

    struct MapVisitor<K, V> {
        k: PhantomData<K>,
        v: PhantomData<V>,
    }

    impl<'de, K, V> Visitor<'de> for MapVisitor<K, V>
    where
        K: Eq + Hash + FromStr,
        K::Err: Display,
        V: Deserialize<'de>,
    {
        type Value = HashMap<K, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map")
        }

        fn visit_map<A>(self, mut input: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut map = HashMap::new();
            while let Some((k, v)) =
                input.next_entry_seed(KeySeed { k: PhantomData }, PhantomData)?
            {
                map.insert(k, v);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(MapVisitor {
        k: PhantomData,
        v: PhantomData,
    })
}
