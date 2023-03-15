//! Artifacts of the PostGuard protocol.
//!
//! This module implements constant-time serde serialization and deserialization for artifacts.
//!
//! # Notes
//!
//! Some artifacts do no require serialization to be constant-time, but we want to limit the
//! dependency graph.

use crate::identity::Policy;
use crate::util::open_ct;
use base64ct::{Base64, Encoding};
use core::fmt;
use ibe::{
    kem::{cgw_kv::CGWKV, mkem::Ciphertext as MkemCt, IBKEM},
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

pub(crate) fn serialize_bin_or_b64<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        let mut enc_buf = vec![0u8; b64len(val.as_ref().len())];
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

pub(crate) fn deserialize_bin_or_b64<'de, D: Deserializer<'de>>(
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

/// Master public keys.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<K: IBKEM>(pub K::Pk);

/// Secret keys.
#[derive(Debug, Clone, Copy)]
pub struct SecretKey<K: IBKEM>(pub K::Sk);

/// User secret keys.
#[derive(Debug, Clone)]
pub struct UserSecretKey<K: IBKEM>(pub K::Usk);

/// Ciphertexts.
#[derive(Debug, Clone)]
pub struct Ciphertext<K: IBKEM>(pub K::Ct);

/// Multi-recipient ciphertexts.
#[derive(Debug, Clone)]
pub struct MultiRecipientCiphertext<K: IBKEM>(pub MkemCt<K>);

// Note:
// We cannot make these implementations generic over the scheme parameter because of a constant
// expression depending on a generic parameter, see https://github.com/rust-lang/rust/issues/68436.
// For now, the solutions are these deserialize impl macros, creating encoding/decoding buffer for
// each scheme specifically.

/// Implements [`serde::ser::Serialize`] and [`serde::de::Deserialize`] for encapsulation wrapper types.
macro_rules! impl_serialize {
    ($type: ty, $inner: ty) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_bin_or_b64(&self.0.to_bytes(), serializer)
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
impl_serialize!(SecretKey<CGWKV>, <CGWKV as IBKEM>::Sk);
impl_serialize!(UserSecretKey<CGWKV>, <CGWKV as IBKEM>::Usk);
impl_serialize!(Ciphertext<CGWKV>, <CGWKV as IBKEM>::Ct);
impl_serialize!(MultiRecipientCiphertext<CGWKV>, MkemCt<CGWKV>);

/// Identity-based signing key including its claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyExt {
    /// The signing key.
    pub key: SigningKey,

    /// The [`Policy`] associated with this signing key.
    ///
    /// The timestamp represents the issuing time by the PKG.
    /// The identity is the identity for whom the key is issued.
    pub policy: Policy,
}

/// Identity-based signing keys.
#[derive(Debug, Clone)]
pub struct SigningKey(pub ibs::gg::UserSecretKey);

impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bincode::serialize(&self.0).map_err(|e| {
            serde::ser::Error::custom(format!("could not serialize signing key: {e}"))
        })?;

        debug_assert_eq!(bytes.len(), ibs::gg::USK_BYTES);

        serialize_bin_or_b64(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut buf = [0u8; ibs::gg::USK_BYTES];
        deserialize_bin_or_b64(&mut buf, deserializer)?;

        let usk = bincode::deserialize(&buf).map_err(|e| {
            serde::de::Error::custom(format!("could not deserialize signing key: {e}"))
        })?;

        Ok(SigningKey(usk))
    }
}

/// Identity-based public master key (signing).
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct VerifyingKey(pub ibs::gg::PublicKey);

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bincode::serialize(&self.0).map_err(|e| {
            serde::ser::Error::custom(format!("could not serialize public key: {e}"))
        })?;

        debug_assert_eq!(bytes.len(), ibs::gg::PK_BYTES);

        serialize_bin_or_b64(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut buf = [0u8; ibs::gg::PK_BYTES];
        deserialize_bin_or_b64(&mut buf, deserializer)?;

        let pk: ibs::gg::PublicKey = bincode::deserialize(&buf).map_err(|e| {
            serde::de::Error::custom(format!("could not deserialize public key: {e}"))
        })?;

        Ok(VerifyingKey(pk))
    }
}

#[cfg(test)]
mod tests {
    mod kem {
        use super::super::*;
        use alloc::vec::Vec;
        use ibe::kem::mkem::MultiRecipient;
        use ibe::Derive;

        struct KEMSetup<K: IBKEM> {
            pk: K::Pk,
            sk: K::Sk,
            ct: K::Ct,
            usk: K::Usk,
            mct: MkemCt<K>,
        }

        fn default_encryption_setup<K>() -> KEMSetup<K>
        where
            K: IBKEM,
            K: MultiRecipient,
        {
            let mut rng = rand::thread_rng();
            let (pk, sk) = K::setup(&mut rng);
            let id1 = <K as IBKEM>::Id::derive_str("test1");
            let id2 = <K as IBKEM>::Id::derive_str("test2");
            let usk = K::extract_usk(Some(&pk), &sk, &id1, &mut rng);
            let (ct, _) = K::encaps(&pk, &id1, &mut rng);
            let ids = [id1, id2];
            let (cts, _) = K::multi_encaps(&pk, &ids, &mut rng);
            let mcts: Vec<MkemCt<K>> = cts.collect();
            let mct = mcts[0].clone();

            KEMSetup {
                pk,
                sk,
                ct,
                usk,
                mct,
            }
        }

        #[test]
        fn test_serialize_pk_json() {
            let KEMSetup { pk, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_pk = PublicKey::<CGWKV>(pk);
            let pk_encoded = serde_json::to_string(&wrapped_pk).unwrap();
            let pk_decoded: PublicKey<CGWKV> = serde_json::from_str(&pk_encoded).unwrap();

            assert_eq!(&wrapped_pk.0, &pk_decoded.0);
        }

        #[test]
        fn test_serialize_sk_json() {
            let KEMSetup { sk, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_sk = SecretKey::<CGWKV>(sk);
            let sk_encoded = serde_json::to_string(&wrapped_sk).unwrap();
            let sk_decoded: SecretKey<CGWKV> = serde_json::from_str(&sk_encoded).unwrap();

            assert_eq!(&wrapped_sk.0, &sk_decoded.0);
        }

        #[test]
        fn test_serialize_usk_json() {
            let KEMSetup { usk, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_usk = UserSecretKey::<CGWKV>(usk);
            let usk_encoded = serde_json::to_string(&wrapped_usk).unwrap();
            let usk_decoded: UserSecretKey<CGWKV> = serde_json::from_str(&usk_encoded).unwrap();

            assert_eq!(&wrapped_usk.0, &usk_decoded.0);
        }

        #[test]
        fn test_serialize_ct_json() {
            let KEMSetup { ct, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_ct = Ciphertext::<CGWKV>(ct);
            let ct_encoded = serde_json::to_string(&wrapped_ct).unwrap();
            let ct_decoded: Ciphertext<CGWKV> = serde_json::from_str(&ct_encoded).unwrap();

            assert_eq!(&wrapped_ct.0, &ct_decoded.0);
        }

        #[test]
        fn test_serialize_mkemct_json() {
            let KEMSetup { mct, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_mct = MultiRecipientCiphertext::<CGWKV>(mct);
            let mct_encoded = serde_json::to_string(&wrapped_mct).unwrap();
            let mct_decoded: MultiRecipientCiphertext<CGWKV> =
                serde_json::from_str(&mct_encoded).unwrap();

            assert_eq!(&wrapped_mct.0.to_bytes(), &mct_decoded.0.to_bytes());
        }

        #[test]
        fn test_serialize_pk_bin() {
            let KEMSetup { pk, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_pk = PublicKey::<CGWKV>(pk);
            let pk_encoded = bincode::serialize(&wrapped_pk).unwrap();
            let pk_decoded: PublicKey<CGWKV> = bincode::deserialize(&pk_encoded[..]).unwrap();

            assert_eq!(&wrapped_pk.0, &pk_decoded.0);
        }

        #[test]
        fn test_serialize_sk_bin() {
            let KEMSetup { sk, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_sk = SecretKey::<CGWKV>(sk);
            let sk_encoded = bincode::serialize(&wrapped_sk).unwrap();
            let sk_decoded: SecretKey<CGWKV> = bincode::deserialize(&sk_encoded[..]).unwrap();

            assert_eq!(&wrapped_sk.0, &sk_decoded.0);
        }

        #[test]
        fn test_serialize_usk_bin() {
            let KEMSetup { usk, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_usk = UserSecretKey::<CGWKV>(usk);
            let usk_encoded = bincode::serialize(&wrapped_usk).unwrap();
            let usk_decoded: UserSecretKey<CGWKV> = bincode::deserialize(&usk_encoded[..]).unwrap();

            assert_eq!(&wrapped_usk.0, &usk_decoded.0);
        }

        #[test]
        fn test_serialize_ct_bin() {
            let KEMSetup { ct, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_ct = Ciphertext::<CGWKV>(ct);
            let ct_encoded = bincode::serialize(&wrapped_ct).unwrap();
            let ct_decoded: Ciphertext<CGWKV> = bincode::deserialize(&ct_encoded[..]).unwrap();

            assert_eq!(&wrapped_ct.0, &ct_decoded.0);
        }

        #[test]
        fn test_serialize_mkemct_bin() {
            let KEMSetup { mct, .. } = default_encryption_setup::<CGWKV>();

            let wrapped_mct = MultiRecipientCiphertext::<CGWKV>(mct);
            let mct_encoded = bincode::serialize(&wrapped_mct).unwrap();
            let mct_decoded: MultiRecipientCiphertext<CGWKV> =
                bincode::deserialize(&mct_encoded).unwrap();

            assert_eq!(&wrapped_mct.0.to_bytes(), &mct_decoded.0.to_bytes());
        }

        #[test]
        fn test_kem_regression_json() {
            let pk ="\"g2sPj5dg1SH15TwQ9k0YsFrpUJbLgxK67mGezYZeB6Zl22AnTnkmHVXv06E44Ev1qd4nsj6SK3l6O21N/J/0/zM36vZhEF56/Kyt2qd93ovZJHqPqCMmYY3pi2d2DP9vt9w/Y0T7LXOKJZLzFzyoXR+ca/quRbQrJRrvz1YZdz36ehJ1CFO63HbqZhUIE21XjL9KKdx3S91cclj337f/FXNF5uPb+6E/6oKh0VniGPArspFhQ5ca/h+k6DsVgpYXgRohU5jqT3FYtx82OewAMo+GGUEmejGgnJwF/V69y6tH16ohZ24RVetn8F8qKkeYhLfMmnWIsjAoD/TIkznRyuQOBhR6bQhNdFP3WM2Z6a6bt/y8NVqDgGhr+hBrD8los9RZAlMlNYLHQgxiSuj3k84FHdX22QpEiUpXWJttwmzLKJyP1lhhmO98+T5Em347hsvLellKAEUABl3lr+Z5Pu6/RKz0ZOsD3fxeGzbPDtxuzqc3uXbrMe0jpG5kwR8B1lLaSs/aychKaSJ5znt9zllzzXjPIuE/+UTXcjmYmO837UVMajj5pZrPOcuf9mLEBoq82irr21UBzHJawgNAStpdWVz5Ie22dDKytdeJv1S1Se4tiZfbJTpRM0FmIX8ZEyfXwehUWFS5GCnwkwkhWyzWMGeDXb2AT+OLDSH7MqWneh2KqjtW6bBEs0XcyvSLEtApi/NDfJk3OZ0/SAJb3tH2c7HN1X0l+HJxuHtT1sDzg3JVizwJwd53mKwgFAnWDkYRScKdAEv+EM0upC5YVhnUYYLfJ8YhC8RTU4W5cvg7Q9rfKonDmZLnJTr2aRo3D9CpfjUffuxBUoARSwJlH14KlI0Id91I8z/Fy1jo22x1dP7gHSl/fto+tGnbpYvj\"";
            let sk = "\"im1K0e1zoEmOoBtWEhMEFbK7BiQrGYh37ua2FX/bCg+cNyUEsE0ObpqZQG5t4ZAFFMsOR/f2HgLGZRbhHdXLCSIxJ5NzjtVUT5KQrbu81D9n/jUOWF47Mp5Sp+b9WzJiVWaakn7j7HuRH4uRJJTg69W+fhBj8eJFoFJL0FEGLgpyiLR1OTLSN6hrxJxQhfGkOvSAPocMw5SNGdtDS+8MDbnuK5+P/bKlTNgg0Tn5sw0wnQ5hluc4flkrcWv+E0wR98sPiRbpLK5qFYmcttzrafpbacj4RwolTrkr0fgdVzBpVhODC0WmFV07ml8t+Q8l3TBmXuZQNF2hF51d1+LabvEToP+g7NHdYoqw4cqw/7hziz52k3HYQ/oICYL/7mAs1kZxbbxtLRK3/FqleG9RrjFkerfV0P47MKNuOlX5Fl97+3/vu47MKVBGJIDUPeh/jKEczw3Pc2CZN8O6XOmRIsj626Hh3nSZ+W0fmhPTjY8gf4nHpOylHvZIMoAe/REv+KMHOMAFwc19fMGUZN/iXqKRp6Tgvao7/o6w1DJsQigDDnyQPhsWqgGIrV2OCTpKRuIOa16EYafbJFPDMlmRLgdIjw4sWXvnFjI45Oqem02RmhBSArR7HxEb0g1QUkEA/XNZI/l/8R241k4BRWZKebfqhqx5JxIe55F6JsqhvRQ=\"";
            let usk = "\"mXLtWwa0YF2+nhiYn7AvG+Fkf4ih6orDMCnDeXxit4ejBLUkyAY0PowIF/UigkU9CygnZEmw09oFM5DxHjeYXB79ck3V8slKANxwXqxmrShf8YGR6BqpLugZW/jWATKZslKVFeDPs8gh0xCbejdBlX2lJLgNB9M5t/NxSuqnNUyCb/zYPGC1ElE3mcUWu8fsDFfIBFveQ/7b5Y8HQOyEUBwYlAbJmQs9XPSJ19WIWoqZNulhkFlcsjW8cj5cquNvpz4NEXKlkz46YMto+wyafbrcBfDbhDHPDFYEVRzGx1JrQ+tVGlJYskCtHMCzdPYfGROot2NcPcP18WB4oIppe1RBglgkM6uZx2kRYsOmJteHfYhjy5rAUTqG52BXqH24o64RNMWKDlL+/hkkqsMCT6UEvdS18xaQBc5mcQ5Hxcwl+sYuZvyy+3ZyE08zVjjrCvy+qa8DViT4ThAvM0phg6EngAhzZVONEPRuglKsd4LlDtk/Qx+pkjvAdMJvkP2qkqhmyZarWAQWHY5jOEl5t7WQNhKSRJkj4NQLMAZ+cxhQxpNy63+p1ejGsWlcjIejCPTeHjP/IJdtdaIYXjBFqsRUpi1Cd27XapHq3fntAYab+jG0TagGdHJbIMkdR6K+sRgA8QjiQsSEElzhZ/hIEDqxq1QkFllltFNodx+zTO7IowNRgJxUtkUUDRvUmNpRA+L2Wl2/Nv2CW+KNiuizwPDzsGs46c29DR5AYHVPEJOsvkzdHEa/IMxXnuqdSTsl\"";
            let ct = "\"pjhu9vnHq7VoT+O0jftONe+9U7NhJ+jqHxV0KQczBgBQ/gaUO30kaYbSlc4IEQHeqOeUitp1I3JAD+juoprsiau6kKWw6gu0mJp/YsTF3b6SQ0q2Mhl3RxzCuWfWVZR8hR7DcQHlyoG1FMbj8tTE2Hsv8BBb0JghwedYmWXhe/7U+DkEEYQKcHPaq5pVfF1HkKnMdwA935uIULIFXGcC3Z3q56PwDCAjjv+lzkpRAlx8kPgyv9IKdhNHhLfJNuAUkzFzYSy08udRKvq0eCl/VH4mWvmWcbQOMn/BguwdGok=\"";
            let mrct = "\"kDxkcKzqw67KhSGYkN6Lbc3PaZmyZZACvHpk5nnC17hneJUi6rDzmbvi21YJ1nrQuQMA4nIb1uuw2akHVajdv/V56G5fpyYUAzrb6IvltPxQbo/7dBsteYyD+OGwVKEho0zPr3yWVhNt9BGwGJvwXClVmmX2MRYVmQ1Gq55TON91VK/upr8Hr3XWRGwR8lhQjy0etI/v7K7UKp90nhQY4JcXlwk666YoDjhLs+gFCOxUpY1bIswJpDVr9mCXMXujdPqiRpoltYYEhdBInhID0WjA5zxvr4zobNxMSZWfk5eAcCHYxItjHX4FCYqrGcPFc5uOUhWOZmay7iNwjczcmMAlMYbSx3ppfDjGfQd06lSygsATkQmTgCMZrwM=\"";

            let _pk_decoded: PublicKey<CGWKV> = serde_json::from_str(pk).unwrap();
            let _sk_decoded: SecretKey<CGWKV> = serde_json::from_str(sk).unwrap();
            let _ct_decoded: Ciphertext<CGWKV> = serde_json::from_str(ct).unwrap();
            let _usk_decoded: UserSecretKey<CGWKV> = serde_json::from_str(usk).unwrap();
            let _mct_decoded: MultiRecipientCiphertext<CGWKV> = serde_json::from_str(mrct).unwrap();
        }
    }

    mod sign {
        use super::super::{SigningKey, VerifyingKey};
        use ibs::gg::*;
        use rand::Rng;

        struct SignSetup {
            pk: PublicKey,
            sk: SecretKey,
            usk: UserSecretKey,
        }

        fn default_signing_setup() -> SignSetup {
            let mut rng = rand::thread_rng();
            let (pk, sk) = ibs::gg::setup(&mut rng);

            let id = Identity::from(rng.gen::<[u8; IDENTITY_BYTES]>());
            let usk = ibs::gg::keygen(&sk, &id, &mut rng);

            SignSetup { pk, sk, usk }
        }

        #[test]
        fn test_signing_regression() {
            let pk = "\"XMTJUg+94jtBhy/z655djL97gFLeDfANA9mhnQ+2tzE=\"";
            let usk = "\"K3Ijgx5lgGA/wD+/rzVVQ6l4xF4N/zxMQPTbsP4c0wJkf/Q1Q3z8STL0Qg1E+b3upqRKNivYKzPZ0246z09bLst0nqGC69fa6PRpG2kEOAXS8B/h6fI/B/I0D9BfQmbU\"";
            let sk = [
                3, 156, 140, 183, 148, 171, 164, 239, 191, 152, 103, 133, 137, 241, 96, 169, 157,
                199, 137, 169, 187, 204, 85, 118, 79, 35, 52, 83, 37, 217, 230, 13,
            ];

            let _pk: VerifyingKey = serde_json::from_str(&pk).unwrap();
            let _usk: SigningKey = serde_json::from_str(&usk).unwrap();
            let _sk: SecretKey = bincode::deserialize(&sk).unwrap();
        }

        macro_rules! test_serialize {
            ($name: ident, $setup: ident, $type: tt, $ser: path, $de: path, $member: tt) => {
                #[test]
                fn $name() {
                    let setup = $setup();

                    let wrapped = $type(setup.$member.clone());
                    let serialized = $ser(&wrapped).unwrap();
                    let deserialized: $type = $de(&serialized).unwrap();

                    assert_eq!(&setup.$member, &deserialized.0);
                }
            };
        }

        test_serialize!(
            test_serialize_verifying_key_bin,
            default_signing_setup,
            VerifyingKey,
            bincode::serialize,
            bincode::deserialize,
            pk
        );

        test_serialize!(
            test_serialize_signing_key_bin,
            default_signing_setup,
            SigningKey,
            bincode::serialize,
            bincode::deserialize,
            usk
        );

        test_serialize!(
            test_serialize_verifying_key_json,
            default_signing_setup,
            VerifyingKey,
            serde_json::to_string,
            serde_json::from_str,
            pk
        );

        test_serialize!(
            test_serialize_signing_key_json,
            default_signing_setup,
            SigningKey,
            serde_json::to_string,
            serde_json::from_str,
            usk
        );
    }
}
