use crate::stream::{AsyncNewCipher, AsyncStreamCipher};
use crate::Error;
use async_trait::async_trait;
use ctr::cipher::{NewCipher, StreamCipher};

// Async wrapper for RustCrypto's StreamCipher.
pub(crate) struct AsyncCipher<T>(T);

#[async_trait(?Send)]
impl<T> AsyncNewCipher for AsyncCipher<T>
where
    T: NewCipher + StreamCipher,
{
    type Cipher = AsyncCipher<T>;

    async fn new_from_slices(key: &[u8], nonce: &[u8]) -> Result<Self::Cipher, Error> {
        let sym = T::new_from_slices(key, nonce).map_err(|_e| Error::KeyError)?;

        Ok(AsyncCipher::<T>(sym))
    }
}

#[async_trait(?Send)]
impl<T> AsyncStreamCipher for AsyncCipher<T>
where
    T: StreamCipher,
{
    async fn apply_keystream(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data)
    }
}
