//! Executable contract examples (EPIC issue #210).
//!
//! The canonical condiscon examples under `schemas/examples/` are not
//! documentation — they are test vectors against the server's actual parser:
//! every `valid/` example must deserialize into [`pg_core::api::IrmaAuthRequest`]
//! and every `invalid/` example must be rejected. If a change to the request
//! types breaks one of these, a deployed client's requests break the same way;
//! that must be a deliberate, versioned decision.
//!
//! The same examples are validated against `schemas/irma-auth-request.schema.json`
//! by the e2e harness (postguard-e2e), keeping schema and parser in agreement.

use std::fs;
use std::path::PathBuf;

use pg_core::api::IrmaAuthRequest;

fn examples(kind: &str) -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schemas/examples")
        .join(kind);
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let body = fs::read_to_string(&path).expect("read example");
                Some((name, body))
            } else {
                None
            }
        })
        .collect();
    out.sort();
    assert!(
        !out.is_empty(),
        "no {kind} examples found in {} — an empty contract is a failing contract",
        dir.display()
    );
    out
}

#[test]
fn valid_examples_parse() {
    for (name, body) in examples("valid") {
        serde_json::from_str::<IrmaAuthRequest>(&body).unwrap_or_else(|e| {
            panic!("valid/{name} must parse as IrmaAuthRequest but was rejected: {e}")
        });
    }
}

#[test]
fn invalid_examples_are_rejected() {
    for (name, body) in examples("invalid") {
        assert!(
            serde_json::from_str::<IrmaAuthRequest>(&body).is_err(),
            "invalid/{name} parsed successfully — either the parser got laxer \
                (a silent contract widening) or the example is wrong"
        );
    }
}
