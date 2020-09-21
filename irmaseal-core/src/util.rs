use crate::*;
use arrayvec::{Array, ArrayVec};

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
    fn read_byte(&mut self) -> Result<u8, Error> {
        if self.buf.len() < self.i {
            return Err(Error::EndOfStream);
        }

        unsafe {
            let res = *self.buf.get_unchecked(self.i);
            self.i += 1;

            Ok(res)
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], Error> {
        if self.i >= self.buf.len() {
            return Err(Error::EndOfStream);
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

impl<A: Array<Item = u8>> Writable for ArrayVec<A> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        unsafe {
            let len = self.len();

            if len + data.len() > A::CAPACITY {
                return Err(Error::UpstreamWritableError);
            }

            let tail = core::slice::from_raw_parts_mut(self.get_unchecked_mut(len), data.len());
            tail.copy_from_slice(data);

            self.set_len(len + data.len());
        }
        Ok(())
    }
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

// We don't want serialize 64 bit numbers as JSON numbers
// due to 64 bit numbers not fitting in JSON.
// https://github.com/serde-rs/json/issues/329
pub mod u64_ser {
    use arrayvec::{ArrayString};
    use serde::{de, Serializer, Deserialize, Deserializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
        where D: Deserializer<'de>
    {
        ArrayString::<[u8; 32]>::deserialize(deserializer)?.parse().map_err(de::Error::custom)
    }
}