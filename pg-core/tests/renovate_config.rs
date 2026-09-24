//! Pins the shape of root `renovate.json` (#448, graduated from #254).
//!
//! The App is hosted, not self-hosted, so nothing in this tree runs it; the
//! only backstop against a well-meaning edit widening or dropping a rule is
//! this test. Three things are pinned: the file still extends the fleet
//! preset at `github>encryption4all/renovate-config` (so first-party packages
//! stay disabled fleet-wide without this repo repeating that list), the
//! `pg-compat/Cargo.toml` rule that disables `pg-core` is still present (the
//! belt-and-braces pin on the wire-compat gate's published readers --
//! `pg-compat/tests/support_window.rs`'s `no_two_pinned_readers_share_a_minor_line`
//! is the other side of that gate), and no rule anywhere sets
//! `"automerge": true` (`postguard` and `postguard-js` both require one
//! review, which a bot cannot give -- #254).
//!
//! `serde_json` is already a `[dependencies]` entry of `pg-core` (for wire
//! metadata), so this reads the file as JSON rather than adding a parser or
//! falling back to string matching.
//!
//! ```text
//! cargo test --manifest-path pg-core/Cargo.toml --test renovate_config
//! ```

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn renovate_json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("renovate.json")
}

fn renovate_json() -> Value {
    let path = renovate_json_path();
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[test]
fn extends_the_fleet_preset() {
    let config = renovate_json();
    let extends = config
        .get("extends")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "{} has no top-level `extends` array",
                renovate_json_path().display()
            )
        });

    let names_preset = extends
        .iter()
        .any(|v| v.as_str() == Some("github>encryption4all/renovate-config"));

    assert!(
        names_preset,
        "{} no longer extends `github>encryption4all/renovate-config`, so this repo stops \
         inheriting the fleet-wide schedule, grouping and first-party-package rules -- see #254",
        renovate_json_path().display(),
    );
}

/// The rule this repo owns on top of the preset: `pg-compat`'s `=`-exact pins
/// on published `pg-core` releases are the wire-compat gate's readers, and a
/// routine bump there would silently move what HEAD is checked against.
#[test]
fn pg_compat_cargo_toml_disables_pg_core() {
    let config = renovate_json();
    let rules = config
        .get("packageRules")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "{} has no `packageRules` array",
                renovate_json_path().display()
            )
        });

    let matches = rules.iter().any(|rule| {
        let matches_file = rule
            .get("matchFileNames")
            .and_then(Value::as_array)
            .is_some_and(|names| {
                names
                    .iter()
                    .any(|n| n.as_str() == Some("pg-compat/Cargo.toml"))
            });
        let matches_package = rule
            .get("matchPackageNames")
            .and_then(Value::as_array)
            .is_some_and(|names| names.iter().any(|n| n.as_str() == Some("pg-core")));
        let disabled = rule.get("enabled").and_then(Value::as_bool) == Some(false);

        matches_file && matches_package && disabled
    });

    assert!(
        matches,
        "{} lost the packageRules entry that matches pg-compat/Cargo.toml + pg-core and sets \
         `enabled: false` -- without it a routine bump can move the wire-compat gate's published \
         readers out from under `no_two_pinned_readers_share_a_minor_line`",
        renovate_json_path().display(),
    );
}

/// `postguard` and `postguard-js` both require one review before merge, which
/// a bot cannot give, so no rule anywhere -- not just at the top level -- may
/// turn automerge on.
#[test]
fn automerge_never_turns_on() {
    let config = renovate_json();

    assert!(
        !contains_automerge_true(&config),
        "{} sets `automerge: true` somewhere; postguard requires one human review per PR and a \
         bot cannot supply it -- see #254",
        renovate_json_path().display(),
    );
}

fn contains_automerge_true(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(k, v)| {
            (k == "automerge" && v.as_bool() == Some(true)) || contains_automerge_true(v)
        }),
        Value::Array(items) => items.iter().any(contains_automerge_true),
        _ => false,
    }
}
