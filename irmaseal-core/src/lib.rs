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

/// Trait to implement AsyncWrite for a non-async data type.
/// When this trait is implemented, IntoAsyncWrite can be used
/// to convert it to AsyncWrite.
pub trait AsyncWritable {
    fn write(&mut self, buf: &[u8]) -> Result<usize, futures::io::Error>;
}

/// Struct to convert AsyncWritable into AsyncWrite
pub struct IntoAsyncWrite<W: AsyncWritable + Unpin>(W);

impl<'a, W: AsyncWritable + Unpin> AsyncWrite for IntoAsyncWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, futures::io::Error>> {
        let this = &mut (*self);
        Poll::Ready(this.0.write(buf))
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

impl<W: AsyncWritable + Unpin> From<W> for IntoAsyncWrite<W> {
    fn from(w: W) -> Self {
        IntoAsyncWrite { 0: w }
    }
}

impl<W: AsyncWritable + Unpin> IntoAsyncWrite<W> {
    pub fn into_inner(self) -> W {
        self.0
    }
}
