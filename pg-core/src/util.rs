use crate::consts::*;
use crate::error::Error;
use alloc::format;
use alloc::string::String;

/// Serde skip helper: returns true when the value is false.
pub(crate) fn is_false(v: &bool) -> bool {
    !v
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

/// Checked variant of slice::split_at: returns a FormatViolation instead of
/// panicking when `mid` is out of bounds. Use this on any slice derived from
/// untrusted (attacker-controllable) ciphertext.
pub(crate) fn try_split_at<'a>(
    b: &'a [u8],
    mid: usize,
    what: &'static str,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    if mid > b.len() {
        return Err(Error::FormatViolation(format!(
            "{what} truncated: need {mid} bytes, have {}",
            b.len()
        )));
    }
    Ok(b.split_at(mid))
}

pub(crate) fn preamble_checked(preamble: &[u8]) -> Result<(u16, usize), Error> {
    if preamble.len() != PREAMBLE_SIZE || preamble[..PRELUDE_SIZE] != PRELUDE {
        return Err(Error::NotPostGuard);
    }

    let version = u16::from_be_bytes(
        preamble[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
            .try_into()
            .map_err(|_e| Error::FormatViolation(String::from("version")))?,
    );

    if version != VERSION_V3 {
        return Err(Error::IncorrectVersion {
            expected: VERSION_V3,
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
