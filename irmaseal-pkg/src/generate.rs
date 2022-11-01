use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::{kem::IBKEM, Compress};

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::{opts::*, PKGError};

fn write_owned<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(contents.as_ref())
}

pub fn exec(gen_opts: &GenOpts) -> Result<(), PKGError> {
    let mut rng = rand::thread_rng();

    let GenOpts {
        scheme,
        secret,
        public,
    } = gen_opts;

    match scheme.as_ref() {
        "2" => {
            let (pk, sk) = CGWKV::setup(&mut rng);
            write_owned(public, pk.to_bytes().as_ref())?;
            write_owned(secret, sk.to_bytes().as_ref())?;
            println!("Written {} and {}.", public, secret);
        }
        x => {
            return Err(PKGError::InvalidVersion(x.into()));
        }
    };

    Ok(())
}
