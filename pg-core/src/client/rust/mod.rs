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
use crate::identity::EncryptionPolicy;

use aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use ibe::kem::cgw_kv::CGWKV;
use ibs::gg::Signer;
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
        let id = h_sig_ext.pol.derive_ibs()?;

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
            pub_id: h_sig_ext.pol,
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
    ) -> Result<(Vec<u8>, VerificationResult), Error> {
        let rec_info = self
            .header
            .recipients
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = &ss.0[..KEY_SIZE];

        let Algorithm::Aes128Gcm(iv) = self.header.algo;

        let aead = Aes128Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(&iv.0);

        let plain = aead.decrypt(nonce, &*self.r)?;

        let msg: MessageAndSignature = bincode::deserialize(&plain)?;
        let id = msg.sig.pol.derive_ibs()?;

        if !self
            .verifier
            .chain(&msg.message)
            .verify(&self.vk.0, &msg.sig.sig, &id)
        {
            return Err(Error::IncorrectSignature);
        }

        debug_assert_eq!(self.config.message_len, msg.message.len());

        let private = if self.pub_id == msg.sig.pol {
            None
        } else {
            Some(msg.sig.pol)
        };

        Ok((
            msg.message,
            VerificationResult {
                public: self.pub_id,
                private,
            },
        ))
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

        // Alice email
        let pub_sign_key = &setup.signing_keys[0];
        // Alice bsn
        let priv_sign_key = &setup.signing_keys[1];

        let input = b"SECRET DATA";
        let sealed = Sealer::<_, SealerMemoryConfig>::new(
            &setup.ibe_pk,
            &setup.policy,
            &pub_sign_key,
            &mut rng,
        )
        .unwrap()
        .with_priv_signing_key(priv_sign_key.clone())
        .seal(input)
        .unwrap();

        // Take Bob's USK for email + name
        let usk = &setup.usks[2];
        let (original, verified_policy) =
            Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &setup.ibs_pk)
                .unwrap()
                .unseal("Bob", &usk)
                .unwrap();

        assert_eq!(&input.to_vec(), &original);

        let expected = VerificationResult {
            public: setup.policies[0].clone(),
            private: Some(setup.policies[1].clone()),
        };

        assert_eq!(&verified_policy, &expected);
    }

    #[test]
    fn test_seal_unseal_wrong_usk() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let pub_sign_key = &setup.signing_keys[0];
        let priv_sign_key = &setup.signing_keys[1];

        let input = b"SECRET DATA";
        let sealed = Sealer::<_, SealerMemoryConfig>::new(
            &setup.ibe_pk,
            &setup.policy,
            &pub_sign_key,
            &mut rng,
        )
        .unwrap()
        .with_priv_signing_key(priv_sign_key.clone())
        .seal(input)
        .unwrap();

        // Take Charlie's USK for only name.
        let usk = &setup.usks[4];
        let res = Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &setup.ibs_pk)
            .unwrap()
            .unseal("Charlie", &usk);

        assert!(matches!(res, Err(Error::KEM)));
    }

    #[test]
    fn test_seal_unseal_wrong_id() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let pub_sign_key = &setup.signing_keys[0];
        let priv_sign_key = &setup.signing_keys[1];

        let input = b"SECRET DATA";
        let sealed = Sealer::<_, SealerMemoryConfig>::new(
            &setup.ibe_pk,
            &setup.policy,
            &pub_sign_key,
            &mut rng,
        )
        .unwrap()
        .with_priv_signing_key(priv_sign_key.clone())
        .seal(input)
        .unwrap();

        let usk = &setup.usks[4];
        let res = Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &setup.ibs_pk)
            .unwrap()
            .unseal("Daniel", &usk);

        assert!(matches!(res, Err(Error::UnknownIdentifier(_))));
    }
}
