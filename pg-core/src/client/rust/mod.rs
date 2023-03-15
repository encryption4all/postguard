//! This module utilizes the symmetric primitives provided by [`Rust
//! Crypto`](https://github.com/RustCrypto). The streaming interface, enabled using the feature
//! `stream` is a small wrapper around [`aead::stream`]. This feature enables an interface
//! to encrypt data using asynchronous byte streams, specifically from an
//! [AsyncRead][`futures::io::AsyncRead`] into an [AsyncWrite][`futures::io::AsyncWrite`].

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::artifacts::{PublicKey, UserSecretKey, VerifyingKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::{EncryptionPolicy, Policy};

use aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use ibe::kem::cgw_kv::CGWKV;
use ibs::gg::{Identity, Signer, IDENTITY_BYTES};
use rand::{CryptoRng, RngCore};

#[cfg(feature = "stream")]
pub mod stream;

/// In-memory configuration for a [`Sealer`].
#[derive(Debug)]
pub struct SealerMemoryConfig {
    key: [u8; KEY_SIZE],
    nonce: [u8; IV_SIZE],
}

/// In-memory configuration for an [`Unsealer`].
#[derive(Debug)]
pub struct UnsealerMemoryConfig {
    message_len: usize,
}

impl SealerConfig for SealerMemoryConfig {}
impl super::sealed::SealerConfig for SealerMemoryConfig {}

impl UnsealerConfig for UnsealerMemoryConfig {}
impl super::sealed::UnsealerConfig for UnsealerMemoryConfig {}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Self::Symmetric
    }
}

impl From<aes_gcm::aes::cipher::InvalidLength> for Error {
    fn from(_: aes_gcm::aes::cipher::InvalidLength) -> Self {
        Self::Symmetric
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageAndSignature {
    message: Vec<u8>,
    sig: SignatureExt,
}

impl<'r, R: RngCore + CryptoRng> Sealer<'r, R, SealerMemoryConfig> {
    /// Create a new [`Sealer`].
    pub fn new(
        mpk: &PublicKey<CGWKV>,
        policies: &EncryptionPolicy,
        pub_sign_key: &SigningKeyExt,
        rng: &'r mut R,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(mpk, policies, rng)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; IV_SIZE];
        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..IV_SIZE]);

        Ok(Self {
            rng,
            header,
            pub_sign_key: pub_sign_key.clone(),
            priv_sign_key: None,
            config: SealerMemoryConfig { key, nonce },
        })
    }

    /// Seals the entire payload.
    pub fn seal(mut self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(message.as_ref().len() + 1024);

        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&VERSION_V3.to_be_bytes());

        self.header = self.header.with_mode(Mode::InMemory {
            size: message.as_ref().len().try_into()?,
        });

        let header_buf = bincode::serialize(&self.header)?;
        out.extend_from_slice(&u32::try_from(header_buf.len())?.to_be_bytes());
        out.extend_from_slice(&header_buf);

        let signer = Signer::new().chain(header_buf);
        let h_sig = signer.clone().sign(&self.pub_sign_key.key.0, self.rng);

        let h_sig_ext = SignatureExt {
            sig: h_sig,
            pol: self.pub_sign_key.policy.clone(),
        };

        let h_sig_ext_bytes = bincode::serialize(&h_sig_ext)?;
        out.extend_from_slice(&u32::try_from(h_sig_ext_bytes.len())?.to_be_bytes());
        out.extend_from_slice(&h_sig_ext_bytes);

        let m_sig_key = self.priv_sign_key.unwrap_or(self.pub_sign_key);
        let m_sig = signer.chain(&message).sign(&m_sig_key.key.0, self.rng);

        let aead = Aes128Gcm::new_from_slice(&self.config.key)?;
        let nonce = Nonce::from_slice(&self.config.nonce);

        let enc_input = bincode::serialize(&MessageAndSignature {
            message: message.as_ref().to_vec(),
            sig: SignatureExt {
                sig: m_sig,
                pol: m_sig_key.policy,
            },
        })?;

        let ciphertext = aead.encrypt(nonce, enc_input.as_ref())?;

        out.extend_from_slice(&ciphertext);

        Ok(out)
    }
}

impl Unsealer<Vec<u8>, UnsealerMemoryConfig> {
    /// Create a new [`Unsealer`].
    pub fn new(input: impl AsRef<[u8]>, vk: &VerifyingKey) -> Result<Self, Error> {
        let b = input.as_ref();
        let (preamble_bytes, b) = b.split_at(PREAMBLE_SIZE);
        let (version, header_len) = preamble_checked(preamble_bytes)?;

        let (header_bytes, b) = b.split_at(header_len);
        let (h_sig_len_bytes, b) = b.split_at(SIG_SIZE_SIZE);
        let h_sig_len = u32::from_be_bytes(h_sig_len_bytes.try_into()?);
        let (h_sig_bytes, ct) = b.split_at(h_sig_len as usize);

        let h_sig_ext: SignatureExt = bincode::deserialize(h_sig_bytes)?;
        let id = Identity::from(h_sig_ext.pol.derive::<IDENTITY_BYTES>()?);

        let verifier = Verifier::default().chain(header_bytes);

        if !verifier.clone().verify(&vk.0, &h_sig_ext.sig, &id) {
            return Err(Error::IncorrectSignature);
        }

        let header: Header = bincode::deserialize(header_bytes)?;
        let message_len = match header.mode {
            Mode::InMemory { size } => size as usize,
            _ => return Err(Error::ModeNotSupported(header.mode)),
        };

        Ok(Self {
            version,
            header,
            r: ct.to_vec(),
            verifier,
            vk: vk.clone(),
            config: UnsealerMemoryConfig { message_len },
        })
    }

    /// Unseals the payload.
    pub fn unseal(
        self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
    ) -> Result<(Vec<u8>, Policy), Error> {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = &ss.0[..KEY_SIZE];

        let Algorithm::Aes128Gcm(iv) = self.header.algo;

        let aead = Aes128Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(&iv.0);

        let plain = aead.decrypt(nonce, &*self.r)?;

        let msg: MessageAndSignature = bincode::deserialize(&plain)?;
        let id = Identity::from(msg.sig.pol.derive::<IDENTITY_BYTES>()?);

        if !self
            .verifier
            .chain(&msg.message)
            .verify(&self.vk.0, &msg.sig.sig, &id)
        {
            return Err(Error::IncorrectSignature);
        }

        debug_assert_eq!(self.config.message_len, msg.message.len());

        Ok((msg.message, msg.sig.pol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestSetup;

    #[test]
    fn test_seal_memory() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let signing_key = setup.signing_keys.get("Alice").unwrap();

        let input = b"SECRET DATA";
        let sealed = Sealer::<_, SealerMemoryConfig>::new(
            &setup.mpk,
            &setup.policies,
            signing_key,
            &mut rng,
        )
        .unwrap()
        .seal(input)
        .unwrap();

        let id = "Bob";
        let usk = setup.usks.get("Bob").unwrap();
        let (original, verified_policy) =
            Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &setup.ibs_pk)
                .unwrap()
                .unseal(id, usk)
                .unwrap();

        assert_eq!(&input.to_vec(), &original);
        assert_eq!(&verified_policy, setup.policies.get("Alice").unwrap());
    }
}
