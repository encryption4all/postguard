use thiserror::Error as ThisError;

/// Errors resulting from IrmaClient operations
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Irma session cancelled")]
    SessionCancelled,
    #[error("Irma session timed out")]
    SessionTimedOut,
    #[error("Irma session not finished")]
    SessionNotFinished(super::sessionresult::SessionStatus),
}
