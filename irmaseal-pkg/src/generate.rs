use clap::ArgMatches;
use ibe::kiltz_vahlis_one::setup;

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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

pub fn exec(m: &ArgMatches) {
    let mut rng = rand::thread_rng();
    let (pk, sk) = setup(&mut rng);

    let public = m.value_of("public").unwrap();
    let secret = m.value_of("secret").unwrap();

    write_owned(public, pk.to_bytes().as_ref());
    write_owned(secret, sk.to_bytes().as_ref());

    println!("Written {} and {}", public, secret);
}
