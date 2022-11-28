//! Implementation for Rust, backed by [Rust Crypto](https://github.com/RustCrypto).

use crate::artifacts::UserSecretKey;
use crate::error::Error;
use crate::header::{Algorithm, Header, Mode};
use crate::identity::Policy;
use crate::util::preamble_checked;
use crate::{consts::*, PublicKey};
use crate::{SealConfig, Sealer};

use aead::Aead;
use aes_gcm::{Aes128Gcm, NewAead, Nonce};
use ibe::kem::cgw_kv::CGWKV;
use rand::{CryptoRng, RngCore};

#[doc(inline)]
pub use crate::SealedPacket;

#[cfg(feature = "rust_stream")]
pub mod stream;

impl From<std::io::Error> for crate::error::Error {
    fn from(e: std::io::Error) -> Self {
        crate::error::Error::StdIO(e)
    }
}

struct SealerConfig {
    key: [u8; KEY_SIZE],
    nonce: [u8; IV_SIZE],
}

impl SealConfig for SealerConfig {}

impl Sealer<SealerConfig> {
    /// Create a new [`Sealer`].
    pub fn new<R: RngCore + CryptoRng>(
        mpk: &PublicKey<CGWKV>,
        policies: &Policy,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..12]);

        Ok(Self {
            header,
            config: SealerConfig { key, nonce },
        })
    }

    /// Seals the payload.
    ///
    /// See [`SealedPacket`] for serialization methods.
    pub fn seal(mut self, input: impl AsRef<[u8]>) -> Result<SealedPacket<Vec<u8>>, Error> {
        self.header = self.header.with_mode(Mode::InMemory {
            size: input
                .as_ref()
                .len()
                .try_into()
                .map_err(|_| Error::ConstraintViolation)?,
        });

        let aead = Aes128Gcm::new_from_slice(&self.config.key).map_err(|_e| Error::KeyError)?;
        let nonce = Nonce::from_slice(&self.config.nonce);

        let ciphertext = aead
            .encrypt(nonce, input.as_ref())
            .map_err(|_e| Error::Symmetric)?;

        Ok(SealedPacket::<Vec<u8>> {
            version: VERSION_V2,
            header: self.header,
            ciphertext,
        })
    }
}

impl SealedPacket<Vec<u8>> {
    /// Serialize to JSON.
    pub fn into_json(self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(Error::Json)
    }

    /// Serialize to binary (MessagePack) format.
    pub fn into_bytes(self) -> Result<Vec<u8>, Error> {
        let mut header_buf = Vec::new();
        self.header.into_bytes(&mut header_buf)?;

        let mut out = Vec::new();
        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(header_buf.len())
                .map_err(|_| Error::ConstraintViolation)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(&self.ciphertext);

        Ok(out)
    }

    /// Deserialize from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(Error::Json)
    }

    /// Deserialize from binary (MessagePack) format.
    pub fn from_bytes(b: impl AsRef<[u8]>) -> Result<Self, Error> {
        let b = b.as_ref();

        let (version, header_len) = preamble_checked(&b[..PREAMBLE_SIZE])?;

        let len = b.len();
        let header_bytes = &b[PREAMBLE_SIZE..PREAMBLE_SIZE + header_len];
        let header = Header::from_bytes(header_bytes)?;

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

        let ss = rec_info.decaps(usk)?;
        let key = &ss.0[..KEY_SIZE];

        let Algorithm::Aes128Gcm(iv) = self.header.algo;

        let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;
        let nonce = Nonce::from_slice(&iv.0);
        aead.decrypt(nonce, &*self.ciphertext)
            .map_err(|_e| Error::Symmetric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestSetup;

    #[test]
    fn test_seal_memory() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::default();

        let input = b"SECRET DATA";
        let packet =
            Sealer::<SealerConfig>::new(&setup.mpk, &setup.policy, &mut rng)?.seal(input)?;
        let out_bin = packet.into_bytes()?;

        let packet2 = SealedPacket::<Vec<u8>>::from_bytes(&out_bin)?;
        let id = "john.doe@example.com";
        let usk = &setup.usks[id];
        let original = packet2.unseal(id, usk)?;

        assert_eq!(&input.to_vec(), &original);

        Ok(())
    }
}
