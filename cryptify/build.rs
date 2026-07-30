fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");

    let lock = std::fs::read_to_string("Cargo.lock").expect("Cargo.lock not readable");
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
