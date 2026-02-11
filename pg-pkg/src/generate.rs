use pg_core::ibs::gg;
use pg_core::kem::cgw_kv::CGWKV;
use pg_core::{kem::IBKEM, Compress};

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{opts::*, PKGError};

fn write_owned<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);

    #[cfg(unix)]
    opts.mode(0o600);

    opts.open(path)?.write_all(contents.as_ref())
}

pub fn exec(gen_opts: &GenOpts) -> Result<(), PKGError> {
    let mut rng = rand::thread_rng();

    let GenOpts {
        scheme,
        ibe_secret_path,
        ibe_public_path,
        ibs_secret_path,
        ibs_public_path,
    } = gen_opts;

    match scheme.as_ref() {
        "3" => {
            let (ibe_pk, ibe_sk) = CGWKV::setup(&mut rng);
            let (ibs_pk, ibs_sk) = gg::setup(&mut rng);

            println!("Keys IBE and IBS key pairs generated.");
            let ibs_pk_bytes = bincode::serialize(&ibs_pk).unwrap();
            let ibs_sk_bytes = bincode::serialize(&ibs_sk).unwrap();

            write_owned(ibe_public_path, ibe_pk.to_bytes().as_ref())?;
            write_owned(ibe_secret_path, ibe_sk.to_bytes().as_ref())?;
            write_owned(ibs_public_path, ibs_pk_bytes)?;
            write_owned(ibs_secret_path, ibs_sk_bytes)?;

            println!("The following keys were written:\n{ibe_public_path}\n{ibe_secret_path}\n{ibs_public_path}\n{ibs_secret_path}");
        }
        x => {
            return Err(PKGError::InvalidVersion(x.into()));
        }
    };

    Ok(())
}
