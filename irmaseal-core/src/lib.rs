#![no_std]

mod artifacts;
mod identity;
mod metadata;

pub mod api;
pub mod util;

#[cfg(feature = "stream")]
pub mod stream;

pub use artifacts::*;
pub use identity::*;
pub use metadata::*;

use core::pin::Pin;
use core::task::{Context, Poll};
use futures::AsyncWrite;

#[derive(Debug)]
pub enum Error {
    NotIRMASEAL,
    IncorrectVersion,
    ConstraintViolation,
    FormatViolation,
    ReadError(futures::io::Error),
    WriteError(futures::io::Error),
}

impl From<Error> for futures::io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::ReadError(e) => e,
            Error::WriteError(e) => e,
            Error::NotIRMASEAL => {
                futures::io::Error::new(futures::io::ErrorKind::Other, "NotIRMASEAL")
            }
            Error::IncorrectVersion => {
                futures::io::Error::new(futures::io::ErrorKind::Other, "IncorrectVersion")
            }
            Error::ConstraintViolation => {
                futures::io::Error::new(futures::io::ErrorKind::Other, "ConstraintViolation")
            }
            Error::FormatViolation => {
                futures::io::Error::new(futures::io::ErrorKind::Other, "FormatViolation")
            }
        }
    }
}

/// A writable resource that accepts chunks of a bytestream.
pub trait Writable {
    /// Write the argument slice to the underlying resource. Needs to consume the entire slice.
    fn write(&mut self, buf: &[u8]) -> Result<(), Error>;
}

impl<W: Writable> From<W> for IntoAsyncWrite<W> {
    fn from(w: W) -> Self {
        IntoAsyncWrite { inner: w }
    }
}

pub struct IntoAsyncWrite<W> {
    inner: W,
}

impl<W> IntoAsyncWrite<W> {
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<'a, W: Writable + Unpin> AsyncWrite for IntoAsyncWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, futures::io::Error>> {
        let this = &mut (*self);
        Poll::Ready(
            this.inner
                .write(buf)
                .map(|_| buf.len())
                .map_err(|err| futures::io::Error::from(err)),
        )
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), futures::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), futures::io::Error>> {
        Poll::Ready(Ok(()))
    }
}
