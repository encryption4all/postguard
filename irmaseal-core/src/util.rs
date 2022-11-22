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
