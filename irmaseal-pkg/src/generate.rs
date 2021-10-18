use ibe::kem::cgw_fo::CGWFO;
use ibe::{kem::IBKEM, Compress};

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::opts::*;

#[cfg(feature = "v1")]
use ibe::kem::kiltz_vahlis_one::KV1;

fn write_owned<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) {
    fn inner(path: &Path, contents: &[u8]) {
        use std::io::Write;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(contents)
            .unwrap()
    }
    inner(path.as_ref(), contents.as_ref())
}

pub fn exec(gen_opts: &GenOpts) {
    let mut rng = rand::thread_rng();

    let GenOpts {
        scheme,
        secret,
        public,
    } = gen_opts;

    match scheme.as_ref() {
        #[cfg(feature = "v1")]
        "1" => {
            let (pk, sk) = KV1::setup(&mut rng);
            write_owned(public, pk.to_bytes().as_ref());
            write_owned(secret, sk.to_bytes().as_ref());
            println!("Written {} and {}.", public, secret);
        }
        "2" => {
            let (pk, sk) = CGWFO::setup(&mut rng);
            write_owned(public, pk.to_bytes().as_ref());
            write_owned(secret, sk.to_bytes().as_ref());
            println!("Written {} and {}.", public, secret);
        }
        _ => {
            println!("Wrong version identifier. Nothing written.");
        }
    }
}
