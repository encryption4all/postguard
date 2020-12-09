use crate::*;
use arrayvec::{Array, ArrayVec};
use futures::io::{Error, ErrorKind};

impl<'a, A: Array<Item = u8>> AsyncWritable for ArrayVec<A> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if self.is_full() {
            Err(Error::new(
                ErrorKind::WriteZero,
                "ArrayVec reached its capacity",
            ))
        } else {
            let mut data = buf;
            if data.len() > self.remaining_capacity() {
                data = &buf[..self.remaining_capacity()];
            }
            let len = self.len();
            unsafe {
                let tail = core::slice::from_raw_parts_mut(self.get_unchecked_mut(len), buf.len());
                tail.copy_from_slice(buf);

                self.set_len(len + buf.len());
            }
            Ok(data.len())
        }
    }
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}
