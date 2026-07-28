//! What the API breaking-change gate actually catches (issue #249).
//!
//! The gate is `.github/workflows/api-diff.yml`, which runs `oasdiff breaking`
//! over `api-description.yaml` and is what stops a careless edit from breaking a
//! deployed client. It is not committed yet: the bot that wrote it has no
//! `workflows: write`, so the YAML waits in a comment on PR #269 for a
//! maintainer to apply. This test is the half that could be committed, and it
//! stands on its own either way.
//!
//! The gate's verdict is decided entirely by two step inputs, `fail-on` and
//! `include-checks`, and getting them wrong fails open: the job goes green and
//! nobody learns that the change it was supposed to stop went through.
//! `fail-on: ERR` alone passes a removed optional response property, a removed
//! request parameter, a changed status code and a dropped response enum value,
//! all of which COMPATIBILITY.md forbids.
//!
//! So the inputs are pinned here rather than only in the workflow: this test
//! mutates the real spec, runs the real engine with the real flags, and asserts
//! which mutations the gate stops. Change [`FAIL_ON`] or [`INCLUDE_CHECKS`]
//! without changing the workflow to match and the two drift apart with nothing
//! to say so; change the workflow without running this and the gate weakens.
//!
//! The engine is not vendored, so the test needs `oasdiff` on `PATH` (or
//! `OASDIFF` pointing at it) and skips when it is absent, which is the case in
//! CI. Install the version the action pins, so a local verdict is CI's verdict:
//!
//! ```text
//! go install github.com/oasdiff/oasdiff@v1.26.1
//! cargo test --manifest-path pg-pkg/Cargo.toml --all-features --test api_gate
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `fail-on` in the workflow's oasdiff step. WARN, not ERR: on this spec only
/// `status` is ever `required`, so removing or renaming any other response
/// property is WARN, and at ERR the gate would pass most of what
/// COMPATIBILITY.md forbids.
const FAIL_ON: &str = "WARN";

/// `include-checks` in the workflow's oasdiff step. Both rate ERR but are
/// opt-in, so they do not run unless named.
const INCLUDE_CHECKS: &str =
    "response-non-success-status-removed,response-property-enum-value-removed";

/// Whether the gate stops a change, i.e. whether the job goes red.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// Additive as far as a deployed client is concerned.
    Passes,
    /// Breaking under COMPATIBILITY.md's `/v2` rules.
    Stops,
}

impl Gate {
    fn verb(&self) -> &'static str {
        match self {
            Gate::Passes => "pass",
            Gate::Stops => "stop",
        }
    }

    fn past(&self) -> &'static str {
        match self {
            Gate::Passes => "passed",
            Gate::Stops => "stopped",
        }
    }
}

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.yaml")
}

/// The `oasdiff` binary, or `None` when it is not installed.
fn oasdiff() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("OASDIFF") {
        return Some(PathBuf::from(explicit));
    }
    let found = Command::new("oasdiff")
        .arg("--help")
        .output()
        .is_ok_and(|out| out.status.success());
    found.then(|| PathBuf::from("oasdiff"))
}

/// Replaces `old` with `new`, requiring `old` to occur exactly once so a spec
/// edit that moves an anchor fails loudly instead of silently mutating nothing.
fn once(text: &str, old: &str, new: &str) -> String {
    assert_eq!(
        text.matches(old).count(),
        1,
        "anchor is not unique in the spec, so this mutation no longer means what it says: {old:?}"
    );
    text.replacen(old, new, 1)
}

/// The half-open byte range of the block starting at `start` and ending where
/// the next `end` begins.
fn block(text: &str, start: &str, end: &str) -> (usize, usize) {
    let from = text.find(start).unwrap_or_else(|| panic!("no {start:?}"));
    let to = text[from..]
        .find(end)
        .unwrap_or_else(|| panic!("no {end:?} after {start:?}"));
    (from, from + to)
}

/// Runs the gate exactly as the workflow's step does: the committed spec as the
/// base, `revision` as the PR's version.
///
/// The entrypoint of `oasdiff/oasdiff-action/breaking@v0.1.10` turns the step
/// inputs into `--allow-external-refs=false --include-checks <checks>
/// --composed=false --fail-on <level>`, so those are the flags used here. Exit 0
/// is a clean diff and exit 1 is "breaking changes found"; anything else is the
/// engine refusing the input, which means the mutation produced a spec oasdiff
/// cannot load and any verdict read off it would be meaningless.
fn gate(oasdiff: &Path, revision: &Path) -> Gate {
    let out = Command::new(oasdiff)
        .arg("breaking")
        .arg(spec_path())
        .arg(revision)
        .arg("--allow-external-refs=false")
        .args(["--include-checks", INCLUDE_CHECKS])
        .arg("--composed=false")
        .args(["--fail-on", FAIL_ON])
        .output()
        .expect("run oasdiff");

    match out.status.code() {
        Some(0) => Gate::Passes,
        Some(1) => Gate::Stops,
        other => panic!(
            "oasdiff exited {other:?} instead of 0 or 1, so it never reached a verdict:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ),
    }
}

// The two response blocks the mutations below anchor on. Both are unique in the
// spec, and `once` fails the test if that ever stops being true.

const TIMESTAMP_PARAMETER: &str = r##"        - name: timestamp
          in: path
          required: true
          description: "Unix seconds; the policy timestamp the key must match."
          schema:
            type: integer
            format: int64
"##;

const RATE_LIMITED_THEN_IRMA_503: &str = r##"        "429":
          description: "Rate limited."
        "503":
          description: "IRMA verification key unavailable (IRMA server unreachable)."
"##;

const JWT_401: &str = r##"        "401":
          description: "Missing/invalid JWT."
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Error"
"##;

// ---------------------------------------------------------------------------
// Additive: allowed on `/v2`, so the gate must let these through. A gate that
// stops them is worse than no gate, because the way around it is to switch it
// off.
// ---------------------------------------------------------------------------

fn add_endpoint(spec: &str) -> String {
    once(
        spec,
        "  /v2/request/key:\n",
        r##"  /v2/request/echo:
    get:
      tags: ["Keys"]
      summary: "Echo"
      operationId: "echo"
      responses:
        "200":
          description: "ok"
  /v2/request/key:
"##,
    )
}

fn add_optional_response_property(spec: &str) -> String {
    once(
        spec,
        "        key:\n          description: |\n            Opaque pg-core-serialized IBE",
        r##"        issuedAt:
          type: integer
          format: int64
          description: "Unix seconds the key was derived."
        key:
          description: |
            Opaque pg-core-serialized IBE"##,
    )
}

fn add_optional_request_property(spec: &str) -> String {
    once(
        spec,
        "      required: [pubSignId]\n      additionalProperties: false\n      properties:\n",
        r##"      required: [pubSignId]
      additionalProperties: false
      properties:
        clientHint:
          type: string
"##,
    )
}

fn add_required_response_property(spec: &str) -> String {
    once(
        spec,
        "      required: [tenant_id]\n      properties:\n",
        r##"      required: [tenant_id, checked_at]
      properties:
        checked_at:
          type: integer
          format: int64
"##,
    )
}

fn add_optional_query_parameter(spec: &str) -> String {
    once(
        spec,
        "      operationId: \"key\"\n      security:",
        r##"      operationId: "key"
      parameters:
        - name: verbose
          in: query
          required: false
          schema:
            type: boolean
      security:"##,
    )
}

fn add_response_status(spec: &str) -> String {
    let with_404 = format!(
        "        \"404\":\n          description: \"No such timestamp.\"\n{RATE_LIMITED_THEN_IRMA_503}"
    );
    once(spec, RATE_LIMITED_THEN_IRMA_503, &with_404)
}

fn edit_a_description(spec: &str) -> String {
    once(
        spec,
        "description: \"Yivi session status.\"",
        "description: \"Yivi session status (see the Yivi docs).\"",
    )
}

/// The escape hatch COMPATIBILITY.md points at: a change `/v2` cannot take
/// additively ships under `/v3` with `/v2` left running. If the gate stopped
/// this there would be no way to make a breaking change at all.
fn add_v3_route_beside_v2(spec: &str) -> String {
    let (from, to) = block(spec, "  /v2/request/key:\n", "  /v2/request/sign/key:\n");
    let v3 = spec[from..to]
        .replacen("  /v2/request/key:", "  /v3/request/key:", 1)
        .replacen("operationId: \"key\"", "operationId: \"keyV3\"", 1);
    once(
        spec,
        "  /v2/request/sign/key:\n",
        &format!("{v3}  /v2/request/sign/key:\n"),
    )
}

// ---------------------------------------------------------------------------
// Breaking: forbidden on `/v2` by COMPATIBILITY.md, so the gate must stop
// these. Each one breaks a client written against today's spec.
// ---------------------------------------------------------------------------

fn remove_route(spec: &str) -> String {
    let (from, to) = block(
        spec,
        "  /v2/request/key/{timestamp}:\n",
        "  /v2/request/key:\n",
    );
    format!("{}{}", &spec[..from], &spec[to..])
}

fn request_property_becomes_required(spec: &str) -> String {
    once(
        spec,
        "      required: [pubSignId]\n",
        "      required: [pubSignId, privSignId]\n",
    )
}

/// A client that handles 401 by refreshing its JWT sees an unhandled 403.
fn change_a_status_code(spec: &str) -> String {
    once(
        spec,
        &format!("{JWT_401}{RATE_LIMITED_THEN_IRMA_503}"),
        &format!(
            "{}{RATE_LIMITED_THEN_IRMA_503}",
            JWT_401.replacen("\"401\":", "\"403\":", 1)
        ),
    )
}

fn remove_a_non_success_status(spec: &str) -> String {
    once(
        spec,
        r##"        "401":
          description: "Unknown, expired or revoked key."
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Error"
"##,
        "",
    )
}

fn remove_a_response_enum_value(spec: &str) -> String {
    once(
        spec,
        "enum: [INITIALIZED, PAIRING, CONNECTED, CANCELLED, DONE, TIMEOUT]",
        "enum: [INITIALIZED, PAIRING, CONNECTED, CANCELLED, DONE]",
    )
}

/// `key` is the IBE user secret key: the payload the endpoint exists to return,
/// and optional only because it is absent until the session is `DONE`.
fn remove_optional_response_property(spec: &str) -> String {
    once(
        spec,
        r##"        key:
          description: |
            Opaque pg-core-serialized IBE user secret key. Present only when
            `status` is `DONE` and `proofStatus` is `VALID`.
"##,
        "",
    )
}

fn rename_optional_response_property(spec: &str) -> String {
    once(
        spec,
        "        proofStatus:\n          $ref: \"#/components/schemas/ProofStatus\"\n        key:\n",
        "        proof_status:\n          $ref: \"#/components/schemas/ProofStatus\"\n        key:\n",
    )
}

fn remove_required_response_property(spec: &str) -> String {
    once(
        spec,
        r##"    KeyResponse:
      type: object
      required: [status]
      properties:
        status:
          $ref: "#/components/schemas/SessionStatus"
"##,
        "    KeyResponse:\n      type: object\n      properties:\n",
    )
}

fn narrow_a_parameter_type(spec: &str) -> String {
    once(
        spec,
        TIMESTAMP_PARAMETER,
        &TIMESTAMP_PARAMETER.replacen("format: int64", "format: int32", 1),
    )
}

fn remove_a_request_parameter(spec: &str) -> String {
    once(
        spec,
        &format!("      parameters:\n{TIMESTAMP_PARAMETER}"),
        "",
    )
}

type Mutation = (&'static str, fn(&str) -> String, Gate);

fn mutations() -> Vec<Mutation> {
    vec![
        ("a new endpoint", add_endpoint, Gate::Passes),
        (
            "a new optional response property",
            add_optional_response_property,
            Gate::Passes,
        ),
        (
            "a new optional request property",
            add_optional_request_property,
            Gate::Passes,
        ),
        (
            "a new required response property",
            add_required_response_property,
            Gate::Passes,
        ),
        (
            "a new optional query parameter",
            add_optional_query_parameter,
            Gate::Passes,
        ),
        ("a new response status", add_response_status, Gate::Passes),
        ("an edited description", edit_a_description, Gate::Passes),
        (
            "a /v3 route beside /v2",
            add_v3_route_beside_v2,
            Gate::Passes,
        ),
        ("a removed route", remove_route, Gate::Stops),
        (
            "a request property becoming required",
            request_property_becomes_required,
            Gate::Stops,
        ),
        ("a changed status code", change_a_status_code, Gate::Stops),
        (
            "a removed non-success status",
            remove_a_non_success_status,
            Gate::Stops,
        ),
        (
            "a removed response enum value",
            remove_a_response_enum_value,
            Gate::Stops,
        ),
        (
            "a removed optional response property",
            remove_optional_response_property,
            Gate::Stops,
        ),
        (
            "a renamed optional response property",
            rename_optional_response_property,
            Gate::Stops,
        ),
        (
            "a removed required response property",
            remove_required_response_property,
            Gate::Stops,
        ),
        (
            "a narrowed parameter type",
            narrow_a_parameter_type,
            Gate::Stops,
        ),
        (
            "a removed request parameter",
            remove_a_request_parameter,
            Gate::Stops,
        ),
    ]
}

/// Every mutation must still edit the spec, whether or not oasdiff is
/// installed, so a spec edit that strands an anchor is caught in CI too.
#[test]
fn every_mutation_still_applies() {
    let spec = fs::read_to_string(spec_path()).expect("read the spec");
    for (name, mutate, _) in mutations() {
        assert_ne!(
            mutate(&spec),
            spec,
            "the mutation for {name} changed nothing, so whatever it asserts is vacuous"
        );
    }
}

#[test]
fn the_gate_stops_breaking_changes_and_passes_additive_ones() {
    let Some(oasdiff) = oasdiff() else {
        eprintln!(
            "skipping: oasdiff is not installed, which is the case on every runner. To run this \
             test, `go install github.com/oasdiff/oasdiff@v1.26.1` (the version the action pins), \
             or set OASDIFF."
        );
        return;
    };

    let spec = fs::read_to_string(spec_path()).expect("read the spec");
    let dir = env::temp_dir().join(format!("pg-pkg-api-gate-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create the scratch directory");

    // The unmutated spec first: without this, a gate that stopped everything
    // would satisfy every Stops case below and only look half broken.
    let unchanged = dir.join("unchanged.yaml");
    fs::write(&unchanged, &spec).expect("write the spec");
    let baseline = gate(&oasdiff, &unchanged);

    let mut wrong = Vec::new();
    if baseline != Gate::Passes {
        wrong.push("  no change at all: the gate should pass it, it stopped it".to_owned());
    }
    for (name, mutate, expected) in mutations() {
        let slug: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let revision = dir.join(format!("{slug}.yaml"));
        fs::write(&revision, mutate(&spec)).expect("write the mutated spec");
        let actual = gate(&oasdiff, &revision);
        if actual != expected {
            wrong.push(format!(
                "  {name}: the gate should {} it, it {} it",
                expected.verb(),
                actual.past()
            ));
        }
    }

    fs::remove_dir_all(&dir).ok();
    assert!(
        wrong.is_empty(),
        "the gate's verdict on {} of {} changes is not what fail-on={FAIL_ON} and \
         include-checks={INCLUDE_CHECKS} are supposed to deliver:\n{}",
        wrong.len(),
        mutations().len() + 1,
        wrong.join("\n"),
    );
}
