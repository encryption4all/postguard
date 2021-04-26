use core::convert::TryInto;

use crate::*;

/// First stage of opening an irmaseal encrypted bytestream.
/// It reads the IRMAseal header and yields the complete header
/// buffer and the metadata.
pub struct MetadataReader {
    // Used to keep track of complete
    header_buf: HeaderBuf,
    // How many bytes we still need to read at least
    remaining_bytes: usize,
}

pub enum MetadataReaderResult {
    Hungry,
    Saturated {
        // If more bytes where written
        // then where necessary for the
        // metadata this indicates
        // how many bytes do not belong
        // to the metadata
        unconsumed: usize,
        // The raw header buffer
        // must be used to start the HMAC
        header: HeaderBuf,
        // The metadata
        metadata: Metadata,
    },
}

impl MetadataReader {
    pub fn new() -> MetadataReader {
        MetadataReader {
            header_buf: HeaderBuf::new(),
            remaining_bytes: PREAMBLE_SIZE,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<MetadataReaderResult, Error> {
        let mut consumed: usize = 0;
        let buf_size = buf.len();

        while self.remaining_bytes != 0 && consumed < buf_size {
            self.header_buf
                .try_push(buf[consumed])
                .map_err(|_| Error::FormatViolation)?;
            consumed += 1;
            self.remaining_bytes -= 1;

            // We have received the complete preamble
            // get the last 4 bytes which are the
            // metadata length.
            let n = self.header_buf.len();
            if n == PREAMBLE_SIZE {
                let bytes = [
                    self.header_buf[n - 4],
                    self.header_buf[n - 3],
                    self.header_buf[n - 2],
                    self.header_buf[n - 1],
                ];
                self.remaining_bytes = u32::from_be_bytes(bytes)
                    .try_into()
                    .map_err(|_| Error::FormatViolation)?;
            }
        }

        if self.remaining_bytes == 0 {
            let m = self.parse_meta_data()?;
            self.remaining_bytes = PREAMBLE_SIZE;
            Ok(MetadataReaderResult::Saturated {
                unconsumed: buf_size - consumed,
                header: core::mem::take(&mut self.header_buf),
                metadata: m,
            })
        } else {
            Ok(MetadataReaderResult::Hungry)
        }
    }

    fn parse_meta_data(&self) -> Result<Metadata, Error> {
        let header_slice: &[u8] = self.header_buf.as_slice();

        if header_slice[0..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let _version = u16::from_be_bytes(
            header_slice[PRELUDE_SIZE..PRELUDE_SIZE + mem::size_of::<u16>()]
                .try_into()
                .unwrap(),
        );

        if _version != VERSION_V1 {
            return Err(Error::IncorrectVersion);
        }

        let meta_len: usize = u32::from_be_bytes(
            header_slice[PRELUDE_SIZE + mem::size_of::<u16>()
                ..PRELUDE_SIZE + mem::size_of::<u16>() + mem::size_of::<u32>()]
                .try_into()
                .unwrap(),
        )
        .try_into()
        .or(Err(Error::ConstraintViolation))?;

        if meta_len > MAX_METADATA_SIZE {
            return Err(Error::FormatViolation);
        }

        let metadata_buf = &header_slice[PREAMBLE_SIZE..PREAMBLE_SIZE + meta_len];

        let metadata = postcard::from_bytes(metadata_buf).or(Err(Error::FormatViolation))?;

        Ok(metadata)
    }
}
