use irmaseal_core::{Error, Readable, Writable};

pub struct FileWriter {
    os: std::fs::File,
}

impl FileWriter {
    pub fn new(os: std::fs::File) -> FileWriter {
        FileWriter { os }
    }
}

impl Writable for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
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

impl Readable for FileReader {
    fn read_byte(&mut self) -> Result<u8, Error> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], Error> {
        use std::io::Read;

        if self.buf.len() < n {
            self.buf.resize(n, 0u8);
        }

        let dst = &mut self.buf.as_mut_slice()[0..n];
        let len = self.is.read(dst).unwrap();

        Ok(&dst[0..len])
    }
}
