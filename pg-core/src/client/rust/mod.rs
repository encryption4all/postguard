//! Implementation for Rust, backed by [Rust Crypto](https://github.com/RustCrypto).

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::Policy;

use aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use ibe::kem::cgw_kv::CGWKV;
use rand::{CryptoRng, RngCore};

#[cfg(feature = "rust_stream")]
pub mod stream;

impl From<std::io::Error> for crate::error::Error {
    fn from(e: std::io::Error) -> Self {
        crate::error::Error::StdIO(e)
    }
}

/// In-memory configuration for a [`Sealer`].
#[derive(Debug)]
pub struct SealerMemoryConfig {
    key: [u8; KEY_SIZE],
    nonce: [u8; IV_SIZE],
}

/// In-memory configuration for an [`Unsealer`].
#[derive(Debug)]
pub struct UnsealerMemoryConfig {}

impl SealerConfig for SealerMemoryConfig {}
impl super::sealed::SealerConfig for SealerMemoryConfig {}

impl UnsealerConfig for UnsealerMemoryConfig {}
impl super::sealed::UnsealerConfig for UnsealerMemoryConfig {}

impl Sealer<SealerMemoryConfig> {
    /// Create a new [`Sealer`].
    pub fn new<R: RngCore + CryptoRng>(
        mpk: &PublicKey<CGWKV>,
        policies: &Policy,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; IV_SIZE];
        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..IV_SIZE]);

        Ok(Self {
            header,
            config: SealerMemoryConfig { key, nonce },
        })
    }

    /// Seals the entire payload.
    ///
    /// See [`PostGuardPacket`] for serialization methods.
    pub fn seal(mut self, input: impl AsRef<[u8]>) -> Result<PostGuardPacket, Error> {
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

        Ok(PostGuardPacket {
            version: VERSION_V2,
            header: self.header,
            ciphertext,
        })
    }
}

impl Unsealer<PostGuardPacket, UnsealerMemoryConfig> {
    /// Create a new [`Unsealer`].
    pub fn new(packet: PostGuardPacket) -> Self {
        Self {
            version: packet.version,
            header: packet.header.clone(),
            r: packet,
            config: UnsealerMemoryConfig {},
        }
    }

    /// Unseals the content of a [`PostGuardPacket`] into a [`Vec`].
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
        aead.decrypt(nonce, &*self.r.ciphertext)
            .map_err(|_e| Error::Symmetric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::rust::UnsealerMemoryConfig as Conf;
    use crate::test::TestSetup;

    #[test]
    fn test_seal_memory() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let input = b"SECRET DATA";
        let packet =
            Sealer::<SealerMemoryConfig>::new(&setup.mpk, &setup.policy, &mut rng)?.seal(input)?;
        let out_bin = packet.into_bytes()?;

        let packet2 = PostGuardPacket::from_bytes(out_bin)?;
        let id = "john.doe@example.com";
        let usk = &setup.usks[id];
        let original = Unsealer::<_, Conf>::new(packet2).unseal(id, usk)?;

        assert_eq!(&input.to_vec(), &original);

        Ok(())
    }
}
