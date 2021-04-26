use std::io::{self, Seek, SeekFrom};

use irmaseal_core::stream::{Readable, StreamError, Writable};
use irmaseal_core::stream::{Sealer, Unsealer};

pub static IRMASEALEXT: &'static str = "irma";

pub struct FileWriter {
    os: std::fs::File,
}

impl FileWriter {
    pub fn new(os: std::fs::File) -> FileWriter {
        FileWriter { os }
    }
}

impl Writable for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        use std::io::Write;
        self.os.write_all(bytes).unwrap();
        Ok(())
    }
}

pub struct FileReader {
    is: std::fs::File,
    buf: Vec<u8>,
}

impl FileReader {
    pub fn new(is: std::fs::File) -> FileReader {
        FileReader { is, buf: vec![] }
    }
}

impl Seek for FileReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.is.seek(pos)
    }
}

impl Readable for FileReader {
    fn read_byte(&mut self) -> Result<u8, StreamError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], StreamError> {
        use std::io::Read;

        if self.buf.len() < n {
            self.buf.resize(n, 0u8);
        }

        let dst = &mut self.buf.as_mut_slice()[0..n];
        let len = self.is.read(dst).unwrap();

        Ok(&dst[0..len])
    }
}

type FileSealer<'a> = Sealer<'a, FileWriter>;

pub struct FileSealerWrite<'a> {
    s: FileSealer<'a>,
}

impl<'a> FileSealerWrite<'a> {
    pub fn new(s: FileSealer<'a>) -> FileSealerWrite<'a> {
        FileSealerWrite { s }
    }
}

impl<'a> std::io::Write for FileSealerWrite<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.s.write(buf).unwrap();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

type FileUnsealer = Unsealer<FileReader>;

pub struct FileUnsealerRead {
    ou: FileUnsealer,
    buf: Vec<u8>,
}

impl FileUnsealerRead {
    pub fn new(ou: FileUnsealer) -> FileUnsealerRead {
        FileUnsealerRead { ou, buf: vec![] }
    }
}

impl std::io::Read for FileUnsealerRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buf.len() == 0 {
            let rbuf_r = match self.ou.read() {
                // End of file is indicated as read with 0 bytes
                Err(StreamError::EndOfStream) => Ok(&[] as &[u8]),
                e => e,
            }
            .unwrap();
            self.buf.extend_from_slice(rbuf_r);
        }

        let min = std::cmp::min(self.buf.len(), buf.len());
        // Better way to do this?
        for n in 0..min {
            buf[n] = self.buf[n];
        }

        self.buf.drain(0..min);

        Ok(min)
    }
}
