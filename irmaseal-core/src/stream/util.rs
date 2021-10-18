use crate::stream::*;
use arrayvec::ArrayVec;

/// A writable resource that accepts chunks of a bytestream.
pub trait Writable {
    /// Write the argument slice to the underlying resource. Needs to consume the entire slice.
    fn write(&mut self, buf: &[u8]) -> Result<(), StreamError>;
}

/// A readable resource that yields chunks of a bytestream.
pub trait Readable {
    /// Read exactly one byte. Will throw `Error::EndOfStream` if that byte
    /// is not available.
    fn read_byte(&mut self) -> Result<u8, StreamError>;

    /// Read **up to** `n` bytes. May yield a slice with a lower number of bytes.
    fn read_bytes(&mut self, n: usize) -> Result<&[u8], StreamError>;

    /// Read **exactly** `n` bytes.
    fn read_bytes_strict(&mut self, n: usize) -> Result<&[u8], StreamError> {
        let res = self.read_bytes(n)?;

        if res.len() < n {
            Err(StreamError::PrematureEndError)
        } else {
            Ok(res)
        }
    }
}

pub struct SliceReader<'a, T> {
    buf: &'a [T],
    i: usize,
}

impl<'a, T> SliceReader<'a, T> {
    pub fn new(buf: &'a [T]) -> SliceReader<'a, T> {
        SliceReader { buf, i: 0 }
    }
}

impl<'a> Readable for SliceReader<'a, u8> {
    fn read_byte(&mut self) -> Result<u8, StreamError> {
        if self.buf.len() < self.i {
            return Err(StreamError::EndOfStream);
        }

        unsafe {
            let res = *self.buf.get_unchecked(self.i);
            self.i += 1;

            Ok(res)
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], StreamError> {
        if self.i >= self.buf.len() {
            return Err(StreamError::EndOfStream);
        }

        let mut end = self.i + n; // Non-inclusive
        if self.buf.len() < end {
            end = self.buf.len();
        }

        let res = &self.buf[self.i..end];
        self.i += n;

        Ok(res)
    }
}

impl<const CAP: usize> Writable for ArrayVec<u8, CAP> {
    fn write(&mut self, data: &[u8]) -> Result<(), StreamError> {
        unsafe {
            let len = self.len();

            if len + data.len() > CAP {
                return Err(StreamError::UpstreamWritableError);
            }

            let tail = core::slice::from_raw_parts_mut(self.get_unchecked_mut(len), data.len());
            tail.copy_from_slice(data);

            self.set_len(len + data.len());
        }
        Ok(())
    }
}
