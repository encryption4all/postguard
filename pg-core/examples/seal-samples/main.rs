//! Seals the deterministic wire-compat sample set with HEAD (issue #260).
//!
//! ```text
//! cargo run -p pg-core --features stream --example seal-samples -- <out-dir>
//! ```
//!
//! The output is the input of the reader half of the bidirectional wire-compat
//! gate (#251): `pg-compat` opens it with published `pg-core` from crates.io,
//! and the Node job in #261 opens it with published `@e4a/pg-wasm` and
//! `@e4a/pg-js`. If HEAD sealed something those readers cannot open, the wire
//! change was not additive.
//!
//! The artifact layout is documented in `pg-compat/README.md`; the set itself
//! lives in `sample_set.rs`.

mod sample_set;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(out_dir) = args.next().map(PathBuf::from) else {
        eprintln!("usage: seal-samples <out-dir>");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("usage: seal-samples <out-dir>");
        return ExitCode::FAILURE;
    }

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("create {}: {e}", out_dir.display());
        return ExitCode::FAILURE;
    }

    for (name, bytes) in sample_set::build() {
        let path = out_dir.join(&name);
        if let Err(e) = fs::write(&path, &bytes) {
            eprintln!("write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("{} ({} bytes)", path.display(), bytes.len());
    }

    ExitCode::SUCCESS
}
