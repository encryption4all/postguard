//! This module implements constant-time serialization and deserialization for the USK and MPK
//! suitable for use in a HTTP API.  MPK serialization does not have to be constant-time, but this
//! way we only require one dependency.

use crate::util::open_ct;
use base64ct::{Base64, Encoding};
use core::fmt;
use core::stringify;
use ibe::{
    kem::{cgw_kv::CGWKV, mkem::MultiRecipientCiphertext as MkemCt, IBKEM},
    Compress,
};
use serde::de::{Error, SeqAccess, Visitor};
use serde::{ser::SerializeTuple, Deserialize, Deserializer, Serialize, Serializer};

// Computes the byte length of raw bytes encoded in (padded) b64.
// We use this to preallocate a buffer to encode into.
const fn b64len(raw_len: usize) -> usize {
    // use next line when unwrap() becomes stable as a const fn:
    // .checked_mul(4).unwrap()
    // this will cause a compiler error when the multiplication overflows,
    // making this function "safe" for all input.
    (((raw_len - 1) / 3) + 1) * 4
}

/// An IRMAseal public key for a system, as generated by the Private Key Generator (PKG).
#[derive(Debug, Clone)]
pub struct PublicKey<K: IBKEM>(pub K::Pk);

/// An IRMAseal user private key, as generated by the Private Key Generator (PKG).
#[derive(Debug, Clone)]
pub struct UserSecretKey<K: IBKEM>(pub K::Usk);

/// An IRMAseal ciphertext.
#[derive(Debug, Clone)]
pub struct Ciphertext<K: IBKEM>(pub K::Ct);

/// An IRMAseal multi-recipient ciphertext.
#[derive(Debug, Clone)]
pub struct MultiRecipientCiphertext<K: IBKEM>(pub MkemCt<K>);

// Note:
// We cannot make these implementations generic parameter over the scheme parameter because of this
// constant expression depending on a generic parameter, see
// https://github.com/rust-lang/rust/issues/68436.
//
// For now, the solutions are these deserialize impl macros, creating encoding/decoding buffer for
// each scheme specifically.

fn serialize_bin_or_b64<S, T, const N: usize>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        let mut enc_buf = [0u8; N];
        let encoded = Base64::encode(val.as_ref(), &mut enc_buf)
            .map_err(|e| serde::ser::Error::custom(format!("base64ct serialization error: {e}")))?;
        serializer.serialize_str(encoded)
    } else {
        let mut seq = serializer.serialize_tuple(val.as_ref().len())?;
        for b in val.as_ref() {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

fn deserialize_bin_or_b64<'de, D: Deserializer<'de>>(
    buf: &mut [u8],
    deserializer: D,
) -> Result<(), D::Error> {
    if deserializer.is_human_readable() {
        struct StrVisitor<'b>(&'b mut [u8]);

        impl<'de> Visitor<'de> for StrVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string of length {}", b64len(self.0.len()))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() != b64len(self.0.len()) {
                    return Err(Error::invalid_length(v.len(), &self));
                }

                Base64::decode(v, self.0).map_err(|e| {
                    serde::de::Error::custom(format!("base64ct decoding error: {e}"))
                })?;

                Ok(())
            }
        }

        deserializer.deserialize_str(StrVisitor(buf))
    } else {
        struct ArrayVisitor<'b>(&'b mut [u8]);

        impl<'de> Visitor<'de> for ArrayVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of length {}", self.0.len())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                for (index, byte) in self.0.iter_mut().enumerate() {
                    *byte = match seq.next_element()? {
                        Some(byte) => byte,
                        None => return Err(Error::invalid_length(index, &self)),
                    };
                }

                Ok(())
            }
        }

        deserializer.deserialize_tuple(buf.len(), ArrayVisitor(buf))
    }
}

/// Implements [`serde::ser::Serialize`] and [`serde::de::Deserialize`] for a wrapped types.
macro_rules! impl_serialize {
    ($type: ty, $inner: ty) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_bin_or_b64::<
                    S,
                    <$inner as Compress>::Output,
                    { b64len(<$inner as Compress>::OUTPUT_SIZE) },
                >(&self.0.to_bytes(), serializer)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let mut buf = [0u8; <$inner as Compress>::OUTPUT_SIZE];
                deserialize_bin_or_b64(&mut buf, deserializer)?;

                let artifact = open_ct(<$inner as Compress>::from_bytes(&buf)).ok_or(
                    serde::de::Error::custom(format!("not a valid {}", stringify!($type))),
                )?;

                Ok(Self(artifact))
            }
        }
    };
}

impl_serialize!(PublicKey<CGWKV>, <CGWKV as IBKEM>::Pk);
impl_serialize!(UserSecretKey<CGWKV>, <CGWKV as IBKEM>::Usk);
impl_serialize!(Ciphertext<CGWKV>, <CGWKV as IBKEM>::Ct);
impl_serialize!(MultiRecipientCiphertext<CGWKV>, MkemCt<CGWKV>);

#[cfg(test)]
mod tests {
    use super::*;
    use ibe::kem::mkem::MultiRecipient;
    use ibe::Derive;

    fn default_setup<K>() -> (K::Pk, K::Sk, K::Ct, K::Usk, MkemCt<K>)
    where
        K: IBKEM,
        K: MultiRecipient<K>,
    {
        let mut rng = rand::thread_rng();
        let (mpk, msk) = K::setup(&mut rng);
        let id1 = <K as IBKEM>::Id::derive_str("test1");
        let id2 = <K as IBKEM>::Id::derive_str("test2");
        let usk = K::extract_usk(Some(&mpk), &msk, &id1, &mut rng);
        let (ct, _) = K::encaps(&mpk, &id1, &mut rng);
        let ids = [id1, id2];
        let (cts, _) = K::multi_encaps(&mpk, &ids, &mut rng);
        let mct: Vec<MkemCt<K>> = cts.collect();

        (mpk, msk, ct, usk, mct[0].clone())
    }

    #[test]
    fn test_serialize_pk_human_readable() {
        let (mpk, _, _, _, _) = default_setup::<CGWKV>();

        let wrapped_pk = PublicKey::<CGWKV>(mpk);
        let pk_encoded = serde_json::to_string(&wrapped_pk).unwrap();
        let pk_decoded: PublicKey<CGWKV> = serde_json::from_str(&pk_encoded).unwrap();

        assert_eq!(&wrapped_pk.0, &pk_decoded.0);
    }

    #[test]
    fn test_serialize_usk_human_readable() {
        let (_, _, _, usk, _) = default_setup::<CGWKV>();

        let wrapped_usk = UserSecretKey::<CGWKV>(usk);
        let usk_encoded = serde_json::to_string(&wrapped_usk).unwrap();
        let usk_decoded: UserSecretKey<CGWKV> = serde_json::from_str(&usk_encoded).unwrap();

        assert_eq!(&wrapped_usk.0, &usk_decoded.0);
    }

    #[test]
    fn test_serialize_ct_human_readable() {
        let (_, _, ct, _, _) = default_setup::<CGWKV>();

        let wrapped_ct = Ciphertext::<CGWKV>(ct);
        let ct_encoded = serde_json::to_string(&wrapped_ct).unwrap();
        let ct_decoded: Ciphertext<CGWKV> = serde_json::from_str(&ct_encoded).unwrap();

        assert_eq!(&wrapped_ct.0, &ct_decoded.0);
    }

    #[test]
    fn test_serialize_mkemct_human_readable() {
        let (_, _, _, _, mct) = default_setup::<CGWKV>();

        let wrapped_mct = MultiRecipientCiphertext::<CGWKV>(mct);
        let mct_encoded = serde_json::to_string(&wrapped_mct).unwrap();
        let mct_decoded: MultiRecipientCiphertext<CGWKV> =
            serde_json::from_str(&mct_encoded).unwrap();

        assert_eq!(&wrapped_mct.0.to_bytes(), &mct_decoded.0.to_bytes());
    }

    #[test]
    fn test_serialize_pk_compact_binary() {
        let (mpk, _, _, _, _) = default_setup::<CGWKV>();

        let wrapped_pk = PublicKey::<CGWKV>(mpk);
        let pk_encoded = rmp_serde::encode::to_vec(&wrapped_pk).unwrap();
        let pk_decoded: PublicKey<CGWKV> = rmp_serde::decode::from_slice(&pk_encoded[..]).unwrap();

        assert_eq!(&wrapped_pk.0, &pk_decoded.0);
    }

    #[test]
    fn test_serialize_usk_compact_binary() {
        let (_, _, _, usk, _) = default_setup::<CGWKV>();

        let wrapped_usk = UserSecretKey::<CGWKV>(usk);
        let usk_encoded = rmp_serde::encode::to_vec(&wrapped_usk).unwrap();
        let usk_decoded: UserSecretKey<CGWKV> =
            rmp_serde::decode::from_slice(&usk_encoded[..]).unwrap();

        assert_eq!(&wrapped_usk.0, &usk_decoded.0);
    }

    #[test]
    fn test_serialize_ct_compact_binary() {
        let (_, _, ct, _, _) = default_setup::<CGWKV>();

        let wrapped_ct = Ciphertext::<CGWKV>(ct);
        let ct_encoded = rmp_serde::encode::to_vec(&wrapped_ct).unwrap();
        let ct_decoded: Ciphertext<CGWKV> = rmp_serde::decode::from_slice(&ct_encoded[..]).unwrap();

        assert_eq!(&wrapped_ct.0, &ct_decoded.0);
    }

    #[test]
    fn test_serialize_mkemct_compact_binary() {
        let (_, _, _, _, mct) = default_setup::<CGWKV>();

        let wrapped_mct = MultiRecipientCiphertext::<CGWKV>(mct);
        let mct_encoded = rmp_serde::encode::to_vec(&wrapped_mct).unwrap();
        let mct_decoded: MultiRecipientCiphertext<CGWKV> =
            rmp_serde::decode::from_slice(&mct_encoded).unwrap();

        assert_eq!(&wrapped_mct.0.to_bytes(), &mct_decoded.0.to_bytes());
    }
}
