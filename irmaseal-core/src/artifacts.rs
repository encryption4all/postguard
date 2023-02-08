//! Artifacts of the IRMAseal protocol.
//!
//! This module implements constant-time serde serialization and deserialization for artifacts.
//!
//! # Notes
//!
//! MPK serialization does not have to be constant-time, but this way we only require one
//! dependency.

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

/// Wrapper type for master public keys.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<K: IBKEM>(pub K::Pk);

/// Wrapper type for secret keys.
#[derive(Debug, Clone, Copy)]
pub struct SecretKey<K: IBKEM>(pub K::Sk);

/// Wrapper type for user secret keys.
#[derive(Debug, Clone)]
pub struct UserSecretKey<K: IBKEM>(pub K::Usk);

/// Wrapper type for ciphertexts.
#[derive(Debug, Clone)]
pub struct Ciphertext<K: IBKEM>(pub K::Ct);

/// Wrapper type for multi-recipient ciphertexts.
#[derive(Debug, Clone)]
pub struct MultiRecipientCiphertext<K: IBKEM>(pub MkemCt<K>);

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

// Note:
// We cannot make these implementations generic over the scheme parameter because of a constant
// expression depending on a generic parameter, see https://github.com/rust-lang/rust/issues/68436.
// For now, the solutions are these deserialize impl macros, creating encoding/decoding buffer for
// each scheme specifically.

/// Implements [`serde::ser::Serialize`] and [`serde::de::Deserialize`] for wrapper types.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ibe::kem::mkem::MultiRecipient;
    use ibe::Derive;

    fn default_setup<K>() -> (K::Pk, K::Sk, K::Ct, K::Usk, MkemCt<K>)
    where
        K: IBKEM,
        K: MultiRecipient,
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
    fn test_serialize_sk_human_readable() {
        let (_, msk, _, _, _) = default_setup::<CGWKV>();

        let wrapped_sk = SecretKey::<CGWKV>(msk);
        let sk_encoded = serde_json::to_string(&wrapped_sk).unwrap();
        let sk_decoded: SecretKey<CGWKV> = serde_json::from_str(&sk_encoded).unwrap();

        assert_eq!(&wrapped_sk.0, &sk_decoded.0);
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
    fn test_serialize_sk_compact_binary() {
        let (_, msk, _, _, _) = default_setup::<CGWKV>();

        let wrapped_sk = SecretKey::<CGWKV>(msk);
        let sk_encoded = rmp_serde::encode::to_vec(&wrapped_sk).unwrap();
        let sk_decoded: SecretKey<CGWKV> = rmp_serde::decode::from_slice(&sk_encoded[..]).unwrap();

        assert_eq!(&wrapped_sk.0, &sk_decoded.0);
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

    #[test]
    fn test_regression_human_readable() {
        let pk ="\"o21LkWDqpJUA5R0YQC37XyU2MR/xMxiG3BoQaVpcByFDsfoPEMLp5QHIIwRjeB4yif39ELXVPoeU4q5a1Ia/FHWGnPeoA0hJskhzm4Tf2kIzGwfIpULL1WtLn1DQUkjFsYcJDOnoAxOvjBRqiGWnf+vq3h1mGf2n2iiAJsbdSFN2vorHJh+f0031jMWYSkQWpCHW/XBB8uyNZaWKIQJ4x3tGjVJbsbh0leY5p330TS0sg+ePlfrNTZAEGr2FuTDuudcY4vz4BJQq9j9cI5lkPY/kbDdpP0dTQH+JD38aaCUYEqfTbornbenHhCBB8wzzpkK1I/DVS4yVfpPSOkKq52/xZy1xiT++C0aUGXbq/AgoNmmrTMeGVYTJzS217N2vgkCDYC7g0UESpv80JLkf7NgXaNkrrmQr2JVr6yTMBfB8hjvvMPuD8yPtLHIt1z1uo7a/NeJZbFboGTdbdsjJN0lJpE+8OHzBmcEk3RntikMLL/8Wr/L44FkUPn05nvu/2MnDBfH0m++FOVJNyMA2VKLABeTrhdeq0yowQRLZD+6IoVRLe6qrt4okOE3HlhUSFYi9vpwJzZ0JbJHBU5aCdE7wwEbE4dtm85Iirdh/KJ1vdcSwaJOt9uOzkt4k+C/KE0wDvnjudYYU668NVR1oZ99GgfteFy8B96hEKzy/1tvDEOvAhDq4adbxrRmRieQZCvyRt/EF74Z7mX08Or6PSUzESiK7VweRdc1dvE8qyDwavBNCADzcAYu9+GxPW4ogEKoQSmUO1d46FSXgBfZwYJV6hX7NgL/Ugl5CSAwjL/md+E5Da3S0P5sr/qdvMe63Ew3QIQXcyrG4DS/V8rCFZ+9XgYppGUBRX9L53hf5ER5CDHb6k35Xn8T/gtX3+kPq\"";
        let sk = "\"hyk9sQ/tPDIgu8bYXu9mjb6El/3edmT4b+OurPyveUozLU86NPyQYcT7RocWiyENFaDUxXbuq1SYU/bTGxkkTFA+vDPwNU/LAF5GgbKlxivyJLqFNOX5oBFnFM6T0CNtuuVUr4ApivAZUj/suuJ6EKMfZLCGOvxHyszp0kKVSQnAZzTIymklAqgvKNziBCWP8+p4PKTIphJbJrQ6j5l2MN4yT0Pc8DoGGo2wo8SSTR2QgxtdOn37ZcOIldJaL3Q/epBc+JBO7emohcvjo57oDxPVc1o/183Qm7phBKKH30ygDOAUHZJB6+Bs19te6mzW4xPtdZrNFBKfLfT3Bq8bJ9RUIeQmIPHUOiHoC2kCl7i4GsRMBl2qId1ePvnh2lwzLEVnWGF19k1DixnZCiJRjMQX6X6DB25VSqB32mdfbEbgbEFD8oHdnMcFQN+j1e2O1Qufd3SJXJtl1BKsEJpoFcbSdPs2l+jpclw5gGd4xQ8H3SJ+ycIazKYskPLIGthvKzXsolUWgZgwmgbRK0eBteOujwlf8ydPdI5asr7Tvxceh3JxLTuUsIbMuD2ULl6WpD2im4tzA8rKBZ1NJ3prXAMituEUaTRgoCOwPCcs5AV7oYYIRIMkn1xsoQnUAN8aEIduaWjg5CU1voYMFsQq935BPraRvptkPsEquT3B6CI=\"";
        let ct = "\"grncB2oxHUi47TwgaffDmzqvWwd2hI5mI2tXnNOCEH/OqN+0ITWVxrFhLWa5a+ePr0f++z7hHl+4mTDEMUDJ3joP0xBUV1xrn0TJum6QF1fe6godMjyukLAVcr61NhFsgdaWcK5wDL/jRWeMJ+WkY29O1s00rMnq0jiQ3KAEYbiz3+dFG8FFJJRk4xds4tG8jv6IhitdhWIXlyU9JF+eMIC9nqSpUBBtmC4M3zhV4OAqmTfLULRjZcLSJrNrbeDWlnzr4MVvw8w4aJTebum3wdjPprzg/QcbtKzLUKOUU7Q=\"";
        let usk = "\"sP/Vn++YOE+FhOpWRij+IWv49dXSFrNHKZNLoU87Rf6U5QpzfdkKueZSDyE5AC+TAIwjRMGwG9aNFXR3Y73dkuhQzNjc0IL9h6IFbptUtcZRvdsONkqh55VrU0VeyYSJrC5hvYghPFGoZSq/KocUR5lmi79CTViUWnntz2w8fI0mKJGTbIDPiLapv/UGtmSfB/y4DfKtsRubGt9BcK2qLxGp5g+3qZ/yJFikX8+8QAjpARrRpLrHkpcccUnUR7ZnpwCtslpRGsVWCb7/mWhGnY1Nz+2b/cCqvshlrjwSd9EUISJikdu19HjZnOQ56yTwBaH6/OYfmuAAnz1qmBU7heHRnvHdLAkdViGe9cFCgzAjsMaDUQRNiAmOkGwC3zraob4oDQubLadB+5Q7UXbuxnzeJrUBrTWt4Hbg/RRyQhIUQo+ZhWQWLzOzeAKxzfbFACcNYkjtHqDxgA4C+a9pDXRTkjFq/IbDMByl+QdlSVEzDdAJ3D0w68FakpvtKYJrjskm4Lfi+Y0d10dUVHrTdSVDygeK963pzWrRMJi5yGsJdGHHQRsytnn7PUqMJMnMBAUkbIL6rxGr2u/wbQRIuBzmEXbt08wRFH1thd4hKbRoZOuxKlZe/TpFDIrditJVuS4SJ0uhm0yx2aa4S8Trvr9f+q4P0tjXBMdpV6jQh3mENN5m8D9rXe028eAg2PWpDj/N4BTgTVT1ZlZw5z7s4zmA5XVpB8th17ifQ3+vt4U+e8mZfJTfCzIUolJxfZ6Z\"";
        let mrct = "\"k6UmczJMHW4JoJ7e65PNvxei2D/ktZ1IaCf7Dju0etTuXQkesn6RF4MS5xsIoUR/hQ3H2hthkf9kLnh50PfpnZMH/HQ0B/VcD9GJ988OPlnIa/C3+h808wah6WdFeIOIk6+gppwinaSEJLG7ONB+QVtujfpBltKLn+/8/4qMRDEMejJUCSYF1GuSByGCHpcaoBIdSqCbabehA58LhrLUQrPfpRcu3IyqI1W27RRFtXzDoPvIo8uWbP4Gq5ZZPN49YsRSlVYwmAf2/PMJA6aGBCqlqNDM6AvLbTcqZN9ssidCSa30v7jBYl4FsMV8edaPqyGTaioBZ810+yi40NdrGw==\"";

        let _pk_decoded: PublicKey<CGWKV> = serde_json::from_str(pk).unwrap();
        let _sk_decoded: SecretKey<CGWKV> = serde_json::from_str(sk).unwrap();
        let _ct_decoded: Ciphertext<CGWKV> = serde_json::from_str(ct).unwrap();
        let _usk_decoded: UserSecretKey<CGWKV> = serde_json::from_str(usk).unwrap();
        let _mct_decoded: MultiRecipientCiphertext<CGWKV> = serde_json::from_str(mrct).unwrap();
    }
}
