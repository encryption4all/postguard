use crate::metadata::*;
use crate::util::generate_iv;
use crate::*;

use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::{mr::MultiRecipient, IBKEM};
use rand::{CryptoRng, Rng};
use std::io::Write;

impl Metadata {
    /// Create a new metadata.
    pub fn new<R: Rng + CryptoRng>(
        pk: &PublicKey<CGWKV>,
        policies: &BTreeMap<String, Policy>,
        rng: &mut R,
    ) -> Result<(Self, SharedSecret), Error> {
        // Map policies to IBE identities.
        let ids = policies
            .values()
            .map(|p| p.derive::<CGWKV>())
            .collect::<Result<Vec<<CGWKV as IBKEM>::Id>, _>>()?;

        // Generate the shared secret and ciphertexts.
        let (cts, ss) = CGWKV::multi_encaps(&pk.0, &ids[..], rng);

        // Generate all RecipientInfo's.
        let recipient_info: BTreeMap<String, RecipientInfo> = policies
            .iter()
            .zip(cts.iter())
            .map(|((rid, policy), ct)| {
                (
                    rid.clone(),
                    RecipientInfo {
                        policy: policy.to_hidden(),
                        ct: ct.to_bytes(),
                    },
                )
            })
            .collect();

        Ok((
            Metadata {
                policies: recipient_info,
                iv: generate_iv(rng),
                chunk_size: SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
            },
            ss,
        ))
    }

    /// Writes binary MessagePack format into a [`std::io::Write`].
    ///
    /// Internally uses the "named" convention, which preserves field names.
    /// Fields names are shortened to limit overhead:
    /// `rs`: map of serialized `RecipientInfo`s with keyed by recipient identifier,
    ///     `p`: serialized `HiddenPolicy`,
    ///     `ct`: associated ciphertext with this policy,
    /// `iv`: 16-byte initialization vector,
    /// `cs`: chunk size in bytes used in the symmetrical encryption.
    pub fn msgpack_into<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&PRELUDE)?;
        w.write_all(&VERSION_V2.to_be_bytes())?;

        let mut meta_vec = Vec::with_capacity(MAX_METADATA_SIZE);
        let mut serializer = rmp_serde::encode::Serializer::new(&mut meta_vec).with_struct_map();

        self.serialize(&mut serializer)
            .map_err(|_e| Error::ConstraintViolation)?;

        // Write the length first.
        w.write_all(
            &u32::try_from(meta_vec.len())
                .map_err(|_e| Error::ConstraintViolation)?
                .to_be_bytes(),
        )?;

        // Write the rest of the metadata.
        w.write_all(&meta_vec)?;

        Ok(())
    }

    /// Serializes the metadata to a json string.
    ///
    /// Should only be used for small metadata or development purposes,
    /// or when compactness is not required.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self).or(Err(Error::FormatViolation))
    }
}
