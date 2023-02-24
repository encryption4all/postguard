//! Implementation for Rust, backed by [Rust Crypto](https://github.com/RustCrypto).

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

#[cfg(feature = "rust_stream")]
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

#[derive(Debug, Serialize, Deserialize)]
struct MessageAndSignature {
    message: Vec<u8>,
    sig: SignatureExt,
}

impl Sealer<SealerMemoryConfig> {
    /// Create a new [`Sealer`].
    pub fn new<R: RngCore + CryptoRng>(
        mpk: &PublicKey<CGWKV>,
        policies: &EncryptionPolicy,
        pub_sign_key: &SigningKeyExt,
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
            pub_sign_key: pub_sign_key.clone(),
            priv_sign_key: None,
            config: SealerMemoryConfig { key, nonce },
        })
    }

    /// Seals the entire payload.
    pub fn seal<R: RngCore + CryptoRng>(
        mut self,
        message: impl AsRef<[u8]>,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(message.as_ref().len() + 1024);

        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&VERSION_V3.to_be_bytes());

        self.header = self.header.with_mode(Mode::InMemory {
            size: message
                .as_ref()
                .len()
                .try_into()
                .map_err(|_| Error::ConstraintViolation)?,
        });

        let header_buf = self.header.into_bytes()?;
        out.extend_from_slice(
            &u32::try_from(header_buf.len())
                .map_err(|_| Error::ConstraintViolation)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&header_buf);

        let h_signer = Signer::new().chain(header_buf);
        let m_signer = h_signer.clone();
        let h_sig = h_signer.sign(&self.pub_sign_key.key.0, rng);

        let h_sig_ext = SignatureExt {
            sig: h_sig,
            pol: self.pub_sign_key.policy.clone(),
        };

        let h_sig_ext_bytes = bincode::serialize(&h_sig_ext).unwrap();
        out.extend_from_slice(
            &u32::try_from(h_sig_ext_bytes.len())
                .map_err(|_| Error::ConstraintViolation)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&h_sig_ext_bytes);

        let m_sig_key = self.priv_sign_key.unwrap_or(self.pub_sign_key);
        let m_sig = m_signer.chain(&message).sign(&m_sig_key.key.0, rng);

        let aead = Aes128Gcm::new_from_slice(&self.config.key).map_err(|_e| Error::KeyError)?;
        let nonce = Nonce::from_slice(&self.config.nonce);

        let enc_input = bincode::serialize(&MessageAndSignature {
            message: message.as_ref().to_vec(),
            sig: SignatureExt {
                sig: m_sig,
                pol: m_sig_key.policy.clone(),
            },
        })
        .unwrap();

        let ciphertext = aead
            .encrypt(nonce, enc_input.as_ref())
            .map_err(|_e| Error::Symmetric)?;

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
        let h_sig_len = u32::from_be_bytes(h_sig_len_bytes.try_into().unwrap());
        let (h_sig_bytes, ct) = b.split_at(h_sig_len as usize);

        let h_sig_ext: SignatureExt = bincode::deserialize(h_sig_bytes).unwrap();
        let id = Identity::from(h_sig_ext.pol.derive::<IDENTITY_BYTES>().unwrap());

        let h_verifier = Verifier::default().chain(&header_bytes);
        let m_verifier = h_verifier.clone();

        if !h_verifier.verify(&vk.0, &h_sig_ext.sig, &id) {
            return Err(Error::IncorrectSignature);
        }

        let header = Header::from_bytes(header_bytes)?;
        let message_len = match header.mode {
            Mode::InMemory { size } => size as usize,
            _ => return Err(Error::ModeNotSupported(header.mode)),
        };

        Ok(Self {
            version,
            header,
            r: ct.to_vec(),
            verifier: m_verifier,
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

        let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;
        let nonce = Nonce::from_slice(&iv.0);

        let plain = aead
            .decrypt(nonce, &*self.r)
            .map_err(|_e| Error::Symmetric)?;

        let msg: MessageAndSignature = bincode::deserialize(&plain).unwrap();
        let id = Identity::from(msg.sig.pol.derive::<IDENTITY_BYTES>().unwrap());
        let verified = self
            .verifier
            .chain(&msg.message)
            .verify(&self.vk.0, &msg.sig.sig, &id);

        if !verified {
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

    // TODO: More testcases,
    // public + private signing setup
    // wrong signatures

    #[test]
    fn test_seal_memory() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let signing_key = setup.signing_keys.get("Alice").unwrap();

        let input = b"SECRET DATA";
        let sealed =
            Sealer::<SealerMemoryConfig>::new(&setup.mpk, &setup.policies, &signing_key, &mut rng)
                .unwrap()
                .seal(input, &mut rng)
                .unwrap();

        let id = "Bob";
        let usk = setup.usks.get("Bob").unwrap();
        let (original, verified_policy) =
            Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &setup.ibs_pk)
                .unwrap()
                .unseal(id, &usk)
                .unwrap();

        assert_eq!(&input.to_vec(), &original);
        assert_eq!(&verified_policy, setup.policies.get("Alice").unwrap());
    }
}
