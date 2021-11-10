use crate::metadata::*;

use ibe::kem::cgw_fo::{CGWFO, CT_BYTES as CGWFO_CT_BYTES};
use serde::ser::SerializeSeq;
use serde::Serialize;
use std::io::Write as StdWrite;

impl<'a> MetadataArgs<'a> {
    /// Writes binary msgPack format into a std::io::Writer.
    ///
    /// Internally uses the "named" convention, which preserves field names.
    /// Fields names are shortened to limit overhead:
    /// `r`: sequence of serialized `RecipientInfo`s,
    ///     `id`: serialized `RecipientIdentifier`,
    ///     `p`: serialized `HiddenPolicy`:
    ///     `ct`: associated ciphertext with this policy,
    /// `iv`: 16-byte initialization vector,
    /// `cs`: chunk size in bytes used in the symmetrical encryption.
    pub fn msgpack_write_into<W: StdWrite>(&self, w: &mut W) -> Result<(), Error> {
        let mut serializer = rmp_serde::encode::Serializer::new(w);
        self.serialize(&mut serializer)
            .map_err(|_e| Error::FormatViolation)
    }

    /// Writes to a pretty json string.
    ///
    /// Should only be used for small metadata or development purposes.
    pub fn write_to_json_string(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(&self).or(Err(Error::FormatViolation)))?
    }
}

/// Serializes encapsulation of a shared secret for each recipient/policy combination.
pub(crate) fn serialize_encaps<S>(list: &Policies, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // TODO: map might be better?
    let mut seq = serializer.serialize_seq(Some(list.0.len()))?;
    for (id, policy) in list.0.into_iter() {
        // TODO: make a real ciphertext for the policy using IBE
        let ct = [7u8; CGWFO_CT_BYTES];

        let recipient_info = RecipientInfo {
            identifier: id.clone(),
            policy: policy.clone(),
            ct,
        };

        seq.serialize_element(&recipient_info)?;
    }

    seq.end()
}
