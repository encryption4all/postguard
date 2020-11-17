use crate::*;
use arrayvec::{Array, ArrayVec};

impl<A: Array<Item = u8>> Writable for ArrayVec<A> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        unsafe {
            let len = self.len();

            if len + data.len() > A::CAPACITY {
                return Err(Error::ConstraintViolation);
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
