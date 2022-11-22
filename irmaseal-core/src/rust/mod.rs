//! Implementation for Rust, backed by [Rust Crypto](https://github.com/RustCrypto).

use crate::artifacts::UserSecretKey;
use crate::error::Error;
use crate::header::{Algorithm, Header, Mode};
use crate::identity::Policy;
use crate::util::preamble_checked;
use crate::{consts::*, PublicKey};

use aead::Aead;
use aes_gcm::{Aes128Gcm, NewAead, Nonce};
use ibe::kem::cgw_kv::CGWKV;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

#[doc(inline)]
pub use crate::SealedPacket;

#[cfg(feature = "rust_stream")]
pub mod stream;

impl From<std::io::Error> for crate::error::Error {
    fn from(e: std::io::Error) -> Self {
        crate::error::Error::StdIO(e)
    }
}

impl SealedPacket<Vec<u8>> {
    /// Create a new SealedPacket.
    pub fn new<R: RngCore + CryptoRng>(
        mpk: &PublicKey<CGWKV>,
        policies: &BTreeMap<String, Policy>,
        rng: &mut R,
        input: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;

        let header = header.with_mode(Mode::InMemory {
            size: input.as_ref().len().try_into().unwrap(),
        });

        let key = &ss.0[..KEY_SIZE];
        let iv = match header.algo {
            Algorithm::Aes128Gcm(iv) => iv,
            _ => return Err(Error::AlgorithmNotSupported(header.algo)),
        };

        let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;
        let nonce = Nonce::from_slice(&iv.0);
        let ciphertext = aead
            .encrypt(nonce, input.as_ref())
            .map_err(|_e| Error::Symmetric)?;

        Ok(Self {
            version: VERSION_V2,
            header,
            ciphertext,
        })
    }

    /// Serialize to JSON.
    pub fn to_json(self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(Error::Json)
    }

    /// Serialize to binary (MessagePack) format.
    pub fn to_bin(self) -> Result<Vec<u8>, Error> {
        let header_buf =
            rmp_serde::to_vec(&self.header).map_err(|e| Error::MessagePack(Box::new(e)))?;

        let mut out = Vec::new();
        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&u32::try_from(header_buf.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(&self.ciphertext);

        Ok(out)
    }

    /// Deserialize from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(Error::Json)
    }

    /// Deserialize from binary (MessagePack) format.
    pub fn from_bin(b: impl AsRef<[u8]>) -> Result<Self, Error> {
        let b = b.as_ref();

        let (version, header_len) = preamble_checked(&b[..PREAMBLE_SIZE])?;

        let len = b.len();
        let header_bytes = &b[PREAMBLE_SIZE..PREAMBLE_SIZE + header_len];
        let header = Header::msgpack_from(header_bytes)?;

        let payload_len = match header.mode {
            Mode::InMemory { size } => size,
            _ => return Err(Error::ModeNotSupported(header.mode)),
        };

        let ct_len = payload_len as usize + TAG_SIZE;
        let ciphertext = b[len - ct_len..].to_vec();

        Ok(SealedPacket {
            version,
            header,
            ciphertext,
        })
    }

    /// Unseals a [`SealedPacket`] into a [`Vec`].
    pub fn unseal(self, ident: &str, usk: &UserSecretKey<CGWKV>) -> Result<Vec<u8>, Error> {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.derive_keys(usk)?;
        let key = &ss.0[..KEY_SIZE];

        let iv = match self.header.algo {
            Algorithm::Aes128Gcm(iv) => iv,
            _ => return Err(Error::AlgorithmNotSupported(self.header.algo)),
        };

        let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;
        let nonce = Nonce::from_slice(&iv.0);
        aead.decrypt(nonce, &*self.ciphertext)
            .map_err(|_e| Error::Symmetric)
    }
}
