use core::convert::TryInto;
use std::io::Read;

use crate::*;

impl Metadata {
    /// Deserialize the metadata from binary messagePack format.
    pub fn msgpack_from<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut tmp = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut tmp).map_err(|_e| Error::NotIRMASEAL)?;

        if tmp[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion);
        }

        let metadata_len = u32::from_be_bytes(
            tmp[PREAMBLE_SIZE - METADATA_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        // Limit the reader, otherwise it would read into possibly a payload
        let meta_reader = r.take(metadata_len as u64);

        rmp_serde::decode::from_read(meta_reader).map_err(|_| Error::FormatViolation)
    }

    /// Deserialize the metadata from a json string.
    pub fn from_json_string(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(|_| Error::FormatViolation)
    }
}
