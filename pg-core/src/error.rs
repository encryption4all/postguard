//! PostGuard errors.

use crate::client::{Algorithm, Mode};

/// An PostGuard error.
#[derive(Debug)]
pub enum Error {
    /// The packet/bytestream does not start with the expected prelude.
    NotPostGuard,
    /// The wrong version specifier was found in the header.
    IncorrectVersion {
        /// The expected version specifier.
        expected: u16,
        /// The found version specifier,
        found: u16,
    },
    /// Serde JSON error.
    Json(serde_json::Error),
    /// Bincode serialization/deserialization error.
    Bincode(bincode::Error),
    /// The recipient identifier was not found in the policies.
    UnknownIdentifier(String),
    /// Incorrect scheme version.
    IncorrectSchemeVersion,
    /// Constraint violation.
    ConstraintViolation,
    /// Format violation.
    FormatViolation(String),
    /// Opaque symmetric encryption error.
    Symmetric,
    /// The symmetric key cannot be initialized using the byte slice.
    KeyError,
    /// The symmetric encryption algorithm is not supported.
    AlgorithmNotSupported(Algorithm),
    /// The encryption mode is not supported.
    ModeNotSupported(Mode),
    /// Opaque key encapsulation error.
    KEM,
    /// The identity-based signature did not verify.
    IncorrectSignature,
    /// Synchronous IO error from the standard library.
    StdIO(std::io::Error),
    /// Asynchronous IO error from the futures crate.
    #[cfg(any(feature = "rust_stream", feature = "web_stream"))]
    FuturesIO(futures::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPostGuard => {
                write!(f, "the bytestream does not start with the expected prelude")
            }
            Self::IncorrectVersion { expected, found } => {
                write!(f, "wrong version, expected: {expected}, found: {found}")
            }
            Self::UnknownIdentifier(ident) => write!(f, "recipient unknown: {ident}"),
            Self::FormatViolation(s) => write!(f, "{s} not (correctly) found in format"),
            Self::Bincode(e) => {
                write!(f, "Bincode error: {e}")
            }
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::IncorrectSchemeVersion => write!(f, "incorrect scheme version"),
            Self::ConstraintViolation => write!(f, "constraint violation"),
            Self::Symmetric => write!(f, "symmetric encryption operation error"),
            Self::KeyError => write!(f, "error importing the key"),
            Self::AlgorithmNotSupported(a) => write!(f, "algorithm is not supported: {a:?}"),
            Self::ModeNotSupported(m) => write!(f, "mode is not supported: {m:?}"),
            Self::KEM => write!(f, "KEM error"),
            Self::IncorrectSignature => write!(f, "incorrect signature"),
            Self::StdIO(e) => write!(f, "standard library IO error: {e}"),
            #[cfg(any(feature = "rust_stream", feature = "web_stream"))]
            Self::FuturesIO(e) => write!(f, "futures IO error: {e}"),
        }
    }
}
