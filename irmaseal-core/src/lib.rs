#![no_std]

mod artifacts;
mod identity;

pub mod util;
pub mod api;

#[cfg(feature = "stream")]
pub mod stream;

pub use artifacts::*;
pub use identity::*;

#[derive(Debug)]
pub enum Error {
    NotIRMASEAL,
    IncorrectVersion,
    ConstraintViolation,
    FormatViolation,
    UpstreamWritableError,
    EndOfStream,
    PrematureEndError,
}

/// A writable resource that accepts chunks of a bytestream.
pub trait Writable {
    /// Write the argument slice to the underlying resource. Needs to consume the entire slice.
    fn write(&mut self, buf: &[u8]) -> Result<(), Error>;
}

/// A readable resource that yields chunks of a bytestream.
pub trait Readable {
    /// Read exactly one byte. Will throw `Error::EndOfStream` if that byte
    /// is not available.
    fn read_byte(&mut self) -> Result<u8, Error>;

    /// Read **up to** `n` bytes. May yield a slice with a lower number of bytes.
    fn read_bytes(&mut self, n: usize) -> Result<&[u8], Error>;

    /// Read **exactly** `n` bytes.
    fn read_bytes_strict(&mut self, n: usize) -> Result<&[u8], Error> {
        let res = self.read_bytes(n)?;

        if res.len() < n {
            Err(Error::PrematureEndError)
        } else {
            Ok(res)
        }
    }
}
