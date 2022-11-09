use irmaseal_core::ibs::gg;
use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::{kem::IBKEM, Compress};

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::opts::*;

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
    let mut rng1 = rand1::thread_rng();
    let mut rng2 = rand2::thread_rng();

    let GenOpts {
        scheme,
        ibe_secret,
        ibe_public,
        ibs_secret,
        ibs_public,
    } = gen_opts;

    match scheme.as_ref() {
        "3" => {
            let (ibe_pk, ibe_sk) = CGWKV::setup(&mut rng2);
            let (ibs_pk, ibs_sk) = gg::setup(&mut rng1);

            let ibs_pk_bytes = rmp_serde::to_vec(&ibs_pk).unwrap();
            let ibs_sk_bytes = rmp_serde::to_vec(&ibs_sk).unwrap();

            write_owned(ibe_public, ibe_pk.to_bytes().as_ref());
            write_owned(ibe_secret, ibe_sk.to_bytes().as_ref());
            write_owned(ibs_public, ibs_pk_bytes);
            write_owned(ibs_secret, ibs_sk_bytes);

            println!("written!");
        }
        _ => {
            println!("Wrong version identifier. Nothing written.");
        }
    }
}
