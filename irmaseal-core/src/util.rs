use crate::consts::*;
use crate::error::Error;

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

pub(crate) fn preamble_checked(preamble: &[u8]) -> Result<(u16, usize), Error> {
    if preamble.len() != PREAMBLE_SIZE || preamble[..PRELUDE_SIZE] != PRELUDE {
        return Err(Error::NotIRMASEAL);
    }

    let version = u16::from_be_bytes(
        preamble[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
            .try_into()
            .map_err(|_e| Error::FormatViolation(String::from("version")))?,
    );

    if version != VERSION_V2 {
        return Err(Error::IncorrectVersion {
            expected: VERSION_V2,
            found: version,
        });
    }

    let header_len = u32::from_be_bytes(
        preamble[PREAMBLE_SIZE - HEADER_SIZE_SIZE..]
            .try_into()
            .map_err(|_e| Error::FormatViolation(String::from("header length")))?,
    ) as usize;

    if header_len > MAX_HEADER_SIZE {
        return Err(Error::ConstraintViolation);
    }

    Ok((version, header_len))
}

#[cfg(any(feature = "rust_stream", feature = "web_stream"))]
pub(crate) mod stream {
    use super::*;
    use crate::header::{Header, Mode};

    pub(crate) fn mode_checked(h: &Header) -> Result<(u32, (u64, Option<u64>)), Error> {
        let (segment_size, size_hint) = match h {
            Header {
                mode:
                    Mode::Streaming {
                        segment_size,
                        size_hint,
                    },
                ..
            } => (segment_size, size_hint),
            _ => return Err(Error::ModeNotSupported(h.mode)),
        };

        if *segment_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(Error::ConstraintViolation);
        }

        Ok((*segment_size, size_hint.clone()))
    }
}
