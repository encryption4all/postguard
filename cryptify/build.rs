use std::path::PathBuf;

/// Locate `Cargo.lock`. Standalone it sits beside this manifest; as a workspace
/// member it sits at the workspace root, so walk up until one turns up.
fn find_lockfile() -> PathBuf {
    let mut dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );
    loop {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            return candidate;
        }
        if !dir.pop() {
            panic!("no Cargo.lock found at or above CARGO_MANIFEST_DIR");
        }
    }
}

fn main() {
    let lockfile = find_lockfile();
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let lock = std::fs::read_to_string(&lockfile).expect("Cargo.lock not readable");
    let version = lock
        .split("[[package]]")
        .find_map(|block| {
            let mut name = None;
            let mut ver = None;
            for line in block.lines() {
                if let Some(rest) = line.strip_prefix("name = \"") {
                    name = rest.strip_suffix('"');
                }
                if let Some(rest) = line.strip_prefix("version = \"") {
                    ver = rest.strip_suffix('"');
                }
            }
            if name == Some("pg-core") {
                ver
            } else {
                None
            }
        })
        .expect(
            "pg-core entry not found in Cargo.lock — PG_CORE_VERSION feeds the \
             X-PostGuard mail header that the Outlook add-in's OnMessageRead \
             launch event filters on (see src/email.rs::XPostGuard).",
        );

    println!("cargo:rustc-env=PG_CORE_VERSION={}", version);
}
