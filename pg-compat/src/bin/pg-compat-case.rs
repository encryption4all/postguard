//! Opens one case of the sample set with one published `pg-core`.
//!
//! ```text
//! pg-compat-case <artifacts-dir> <pg-core-version> <case-name>
//! ```
//!
//! Prints one line per failure and exits 1; exits 0 when the case opens. The
//! gate (`tests/wire_compat.rs`) runs one of these per case so that a reader
//! that aborts on a shifted header only loses its own case.

use std::path::PathBuf;
use std::process::ExitCode;

use pg_compat::{read_manifest, reader};

const USAGE: &str = "usage: pg-compat-case <artifacts-dir> <pg-core-version> <case-name>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir, version, case_name] = args.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);

    let Some(reader) = reader(version) else {
        eprintln!("no reader configured for pg-core {version}");
        return ExitCode::from(2);
    };

    let manifest = read_manifest(&dir);
    let Some(case) = manifest.cases.iter().find(|c| &c.name == case_name) else {
        eprintln!("the sample set has no case named {case_name}");
        return ExitCode::from(2);
    };

    let failures = (reader.verify_case)(&dir, &manifest, case);
    for failure in &failures {
        println!("{failure}");
    }

    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
