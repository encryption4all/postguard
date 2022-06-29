//! This module implements constant-time serialization and deserialization for the USK and MPK
//! suitable for use in a HTTP API.  MPK serialization does not have to be constant-time, but this
//! way we only require one dependency.

use crate::util::open_ct;
use base64ct::{Base64, Encoding};
use ibe::{
    kem::{cgw_kv::CGWKV, IBKEM},
    Compress,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
pub struct MultiRecipientCiphertext<K: IBKEM>(pub ibe::kem::mkem::MultiRecipientCiphertext<K>);

// Note: We cannot make these implementations generic parameter over the scheme parameter because
// of this constant expression depending on a generic parameter, see
// https://github.com/rust-lang/rust/issues/68436.
//
// For now, the solutions are these deserialize impl macros, creating encoding/decoding buffer for
// each scheme specifically.

/// Implements [`serde::ser::Serialize`] and [`serde::de::Deserialize`] for a wrapped artifact type.
macro_rules! impl_serialize {
    ($scheme: ident, $type: ident, $inner: ident) => {
        impl Serialize for $type<$scheme> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    let mut enc_buf =
                        [0u8; b64len(<<$scheme as IBKEM>::$inner as Compress>::OUTPUT_SIZE)];
                    let encoded = Base64::encode(self.0.to_bytes().as_ref(), &mut enc_buf)
                        .map_err(|e| {
                            serde::ser::Error::custom(format!("base64ct serialization error: {e}"))
                        })?;
                    serializer.serialize_str(encoded)
                } else {
                    serializer.serialize_bytes(self.0.to_bytes().as_ref())
                }
            }
        }

        impl<'de> Deserialize<'de> for $type<$scheme> {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                if deserializer.is_human_readable() {
                    let s = <&'de str>::deserialize(deserializer)?;
                    let mut dec_buf = [0u8; <<$scheme as IBKEM>::$inner as Compress>::OUTPUT_SIZE];

                    Base64::decode(s, &mut dec_buf)
                        .map_err(|_e| serde::de::Error::custom("base64ct decoding error"))?;

                    let artifact = open_ct(<$scheme as IBKEM>::$inner::from_bytes(&dec_buf))
                        .ok_or(serde::de::Error::custom("not an artifact"))?;

                    Ok($type(artifact))
                } else {
                    let dec_buf = <&'de [u8]>::deserialize(deserializer)?;
                    let artifact = open_ct(<$scheme as IBKEM>::$inner::from_bytes(
                        &dec_buf.try_into().map_err(|e| {
                            serde::de::Error::custom(format!(
                                "decoded buffer has incorrect size: {e}"
                            ))
                        })?,
                    ))
                    .ok_or(serde::de::Error::custom("not an artifact"))?;

                    Ok($type(artifact))
                }
            }
        }
    };
}
impl_serialize!(CGWKV, PublicKey, Pk);
impl_serialize!(CGWKV, UserSecretKey, Usk);
impl_serialize!(CGWKV, Ciphertext, Ct);

// TODO: MultiRecipientCiphertext serialization

#[cfg(test)]
mod tests {
    use super::*;
    use ibe::Derive;

    fn default_setup<K: IBKEM>() -> (K::Pk, K::Sk, K::Ct, K::Usk) {
        let mut rng = rand::thread_rng();
        let (mpk, msk) = K::setup(&mut rng);
        let id = <K as IBKEM>::Id::derive_str("test");
        let usk = K::extract_usk(Some(&mpk), &msk, &id, &mut rng);
        let (ct, _) = K::encaps(&mpk, &id, &mut rng);

        (mpk, msk, ct, usk)
    }

    #[test]
    fn test_serialize_artifacts_human_readable() {
        let (mpk, _msk, ct, usk) = default_setup::<CGWKV>();

        let wrapped_pk = PublicKey::<CGWKV>(mpk);
        let pk_encoded = serde_json::to_string(&wrapped_pk).unwrap();
        let pk_decoded: PublicKey<CGWKV> = serde_json::from_str(&pk_encoded).unwrap();

        assert_eq!(&wrapped_pk.0, &pk_decoded.0);

        let wrapped_usk = UserSecretKey::<CGWKV>(usk);
        let usk_encoded = serde_json::to_string(&wrapped_usk).unwrap();
        let usk_decoded: UserSecretKey<CGWKV> = serde_json::from_str(&usk_encoded).unwrap();

        assert_eq!(&wrapped_usk.0, &usk_decoded.0);

        let wrapped_ct = Ciphertext::<CGWKV>(ct);
        let ct_encoded = serde_json::to_string(&wrapped_ct).unwrap();
        let ct_decoded: Ciphertext<CGWKV> = serde_json::from_str(&ct_encoded).unwrap();

        assert_eq!(&wrapped_ct.0, &ct_decoded.0);
    }

    #[test]
    fn test_serialize_artifacts_compact_binary() {
        let (mpk, _msk, ct, usk) = default_setup::<CGWKV>();

        let wrapped_pk = PublicKey::<CGWKV>(mpk);
        let pk_encoded = rmp_serde::encode::to_vec(&wrapped_pk).unwrap();
        let pk_decoded: PublicKey<CGWKV> = rmp_serde::decode::from_slice(&pk_encoded[..]).unwrap();

        assert_eq!(&wrapped_pk.0, &pk_decoded.0);

        let wrapped_usk = UserSecretKey::<CGWKV>(usk);
        let usk_encoded = rmp_serde::encode::to_vec(&wrapped_usk).unwrap();
        let usk_decoded: UserSecretKey<CGWKV> =
            rmp_serde::decode::from_slice(&usk_encoded[..]).unwrap();

        assert_eq!(&wrapped_usk.0, &usk_decoded.0);

        let wrapped_ct = Ciphertext::<CGWKV>(ct);
        let ct_encoded = rmp_serde::encode::to_vec(&wrapped_ct).unwrap();
        let ct_decoded: Ciphertext<CGWKV> = rmp_serde::decode::from_slice(&ct_encoded[..]).unwrap();

        assert_eq!(&wrapped_ct.0, &ct_decoded.0);
    }
}
