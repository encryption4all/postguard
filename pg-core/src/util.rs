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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_split_at_splits_on_exact_boundary() {
        let buf = [1u8, 2, 3, 4];
        let (a, b) = try_split_at(&buf, 4, "all").unwrap();
        assert_eq!(a, &buf[..]);
        assert!(b.is_empty());
    }

    #[test]
    fn try_split_at_splits_in_the_middle() {
        let buf = [1u8, 2, 3, 4];
        let (a, b) = try_split_at(&buf, 2, "half").unwrap();
        assert_eq!(a, &[1, 2]);
        assert_eq!(b, &[3, 4]);
    }

    #[test]
    fn try_split_at_zero_is_ok() {
        let buf = [1u8, 2];
        let (a, b) = try_split_at(&buf, 0, "zero").unwrap();
        assert!(a.is_empty());
        assert_eq!(b, &buf[..]);
    }

    #[test]
    fn try_split_at_out_of_bounds_returns_format_violation() {
        let buf = [1u8, 2, 3];
        match try_split_at(&buf, 5, "tag") {
            Err(Error::FormatViolation(msg)) => {
                assert!(msg.contains("tag"), "expected label in message, got {msg:?}");
                assert!(msg.contains('5'), "expected requested length in message, got {msg:?}");
            }
            other => panic!("expected FormatViolation, got {other:?}"),
        }
    }

    #[test]
    fn try_split_at_empty_slice_nonzero_mid_is_err() {
        let buf: [u8; 0] = [];
        assert!(matches!(
            try_split_at(&buf, 1, "empty"),
            Err(Error::FormatViolation(_))
        ));
    }

    #[test]
    fn preamble_checked_rejects_short_input() {
        let short = alloc::vec![0u8; PREAMBLE_SIZE - 1];
        assert!(matches!(preamble_checked(&short), Err(Error::NotPostGuard)));
    }

    #[test]
    fn preamble_checked_rejects_wrong_prelude() {
        let mut buf = alloc::vec![0u8; PREAMBLE_SIZE];
        buf[PRELUDE_SIZE - 1] = 0xFF;
        assert!(matches!(preamble_checked(&buf), Err(Error::NotPostGuard)));
    }
}
