
---

## Agent notes (migrated from the dobby memory repo)

## Overview
`encryption4all/cryptify` is a Rocket/Rust file-upload service: a sender uploads a
file, cryptify PostGuard-seals it for a signed recipient, and emails a notification.
Backend only. `pdf-signature` is a fork sharing the same README, with a divergent
frontend and a slightly different config shape (see that repo's own notes).

## Config
Backend config lives in `conf/config.toml` (prod) and `conf/config.dev.toml` (dev).
Keys: `server_url`, `address`, `data_dir`, `email_from`, `smtp_*`, `allowed_origins`,
`pkg_url`. The backend reads `ROCKET_CONFIG=config.toml` baked into the Dockerfile,
`[global]` profile in `conf/config.toml`. Compose bind-mounts `./conf/config.toml`
to `/app/config.toml:ro`; mutating the bind-mounted file requires a container
restart to take effect.

## Release process
Release-plz automation.

## Build / test
- `cargo check`, `cargo build --release`, `cargo test`, `cargo clippy --all-targets`
  all work from repo root.
- No library target: tests live in `src/**` under `#[cfg(test)] mod tests`.
- CI (`.github/workflows/ci.yml`, `quality` job) runs `cargo fmt --all -- --check`,
  `cargo clippy --all-targets -- -D warnings`, and `cargo test --all-targets` on
  every PR. Run all three locally before pushing; a fmt/clippy failure blocks the PR.
- **Docker build Rust version can lag behind CI's stable toolchain.** The CI
  `Rust quality` job uses `dtolnay/rust-toolchain@stable` (always latest), but the
  Docker `Build (amd64/arm64)` jobs use the pinned `FROM rust:<ver>-slim-trixie` in
  the `Dockerfile`. These can diverge enough that a dependency's build script needs
  a newer Rust than the pinned Docker image ships (happened when `rusqlite`'s
  `bundled` feature started needing `cfg_select`, stabilized in Rust 1.94, while
  Docker was pinned to 1.93). When adding a dep, check whether it needs a newer Rust
  than the Dockerfile's pin and bump the Dockerfile if so. `rust:*-slim-trixie`
  already ships gcc, so `bundled` C compilation works without extra apt installs.
- **Tests that touch `Store` need a tokio runtime.** `Store::new()` spawns a purge
  task via `rocket::tokio::spawn`; under plain `#[test]` it panics with "no reactor
  running". Use `#[rocket::async_test]` and `async fn`, even when the body never
  awaits.

## Dependencies
- cryptify has no IRMA/Yivi client of its own. Attributes arrive already signed
  inside the PostGuard-sealed file and are read back through `pg-core`'s Unsealer,
  so nothing here talks to a Yivi session server.
- `pg-core` depends on the `irma` crate, so `irma` 0.2.1 is still compiled into the
  binary even though cryptify does not declare it (`cargo tree -i irma`). It drags
  in `reqwest` 0.11.27 too, alongside cryptify's own `reqwest` 0.13.4. Dropping the
  direct declaration does not take `irma` out of the build; check `Cargo.toml` to
  tell direct from transitive.

## Running the binary
- Needs a reachable PKG server (`pkg_url`) at startup or it panics on
  `/v2/sign/parameters`. For config tests, prefer a serde-roundtrip unit test over
  booting the server.
- SMTP, `data_dir`, `pkg_url` are all required.

## Request pipeline (build_rocket layering)
- Two seams in `src/main.rs`: `default_figment()` returns the bare
  `rocket::Config::figment()`; `build_rocket(figment, vk)` extracts
  `CryptifyConfig`, computes body-size limits from `config.chunk_size()`, merges
  them, then constructs `rocket::custom(...)`.
- **Do NOT extract config inside `default_figment()`.** Integration tests layer
  config on top with `default_figment().merge(...)`. Extracting too early panics
  with `MissingField`.
- Body-size headroom is `chunk_size + 1 MiB` on `bytes`, `data-form`, `file`.
  Per-request reads are still capped by `data.open((end - start).bytes())` in
  `upload_chunk`.

## Upload flow and state lifetime
- `POST /fileupload/init`: in-memory `FileState` keyed by UUID. Sender unknown at
  this point.
- `PUT /fileupload/<uuid>`: write a chunk (<= 1 MiB), advance `state.uploaded`. The
  cryptify token rolls per chunk as `SHA256(prev_token || chunk)`.
- `POST /fileupload/finalize/<uuid>`: run the postguard Unsealer over the whole
  file to extract attributes; `sender` (`pbdf.sidn-pbdf.email.email`) becomes
  known.
- **Purge timer:** `state.expirations` (a `BTreeMap` populated by the shared
  `insert_session` helper, which `Store::create` calls with
  `Instant::now() + self.shared.idle_ttl` and `Store::restore_sessions` with
  whatever is left of a persisted session's window) is what `purge_task` walks.
  `idle_ttl` defaults to `DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS`
  (`60 * 60`, 1 hour); this is a resettable idle timeout, not a hard deadline from
  creation. `Store::touch` removes the old `expirations` key and
  re-inserts `Instant::now() + idle_ttl` on each chunk PUT and status check, so the
  hour counts from the last activity (see the `touch_extends_eviction_deadline` test
  in `src/store.rs`). `FileState.expires` (current_time + 14d) is NOT what drives
  eviction; it's a different field, never read by the purge loop. When tracing
  eviction, follow `state.expirations`.
- Purge does not delete the on-disk file while the process runs. Rejecting at
  finalize must manually `tokio::fs::remove_file` and `store.remove(uuid)`. The
  one place the server does delete an upload file on its own is the boot-time
  sweep below, and only for sessions that expired while it was down.
- The in-memory `HashMap` is still what every request reads, but it is no longer
  empty at boot: `Store::restore_sessions` (postguard#303) rebuilds it from the
  `upload_sessions` rows postguard#302 writes through, so a chunk PUT that
  arrives after a redeploy resumes instead of 404-ing (postguard-website#117).
- **The two clocks a restored session is judged against.** `Instant` cannot
  outlive a process, so the durable stand-in for the idle deadline is
  `last_active_at + idle_ttl`, computed against wall-clock time at boot. A row
  is restored only when that *and* `expires` (the 14-day on-disk deadline) are
  both still in the future, and the idle window is **not** restarted. Downtime
  counts against a session exactly as an idle client would, so a restart cannot
  be used to keep a dead session alive. Everything else loses its row, and loses
  its file in `data_dir/` too, but only when `sender` is still unset. A
  finalized session's file is a completed upload waiting to be downloaded, and
  deleting it would take a live download with it. The sweep only ever names
  files it holds a row for, so a stray file, or the state database itself when a
  deployment keeps it under `data_dir`, is never a candidate.
- A row this binary cannot read back (an unparsable `recipients`, an unknown
  `mail_lang`) is skipped, and its file left alone. Guessing at a value is worse
  than waiting: once its deadlines pass, the expiry branch collects both.
- **`usage_db` is not just usage any more: it names cryptify's whole SQLite state
  database.** One file, one `rusqlite::Connection` behind one `Mutex` (`StateDb`
  in `src/store.rs`), two tables — `usage` and `upload_sessions`. Both schemas are
  created with `CREATE TABLE IF NOT EXISTS` at startup, so an existing
  usage-only database gains the new table in place. `usage_db` unset means both
  stay in memory only (the old behaviour, and what every unit test uses); a
  configured-but-unopenable DB panics at startup. The key name was left alone on
  purpose: renaming it would be an ops-visible change for zero behavioural gain.
- **Do not read the checked-in `conf/config.toml` as prod's config.** It does
  not set `usage_db`, which reads as "persistence is dark in production". That
  is wrong. Per @rubenhensen (postguard#303), prod's config is templated by
  `privacybydesign/postguard-ops`: `procolix/main.tf` sets
  `usage_db = /app/data/usage.db`, bind-mounted to `/opt/cryptify/data`. So both
  usage and session persistence are live in prod, and a claim about what a
  deployment does has to be checked against that repo, not this one. That repo
  404s for the dobby App token, so this line is the maintainers' correction
  rather than something verified here.
- Per-sender usage: the map in `StoreState.usage` is a cache, the table is the
  source of truth, loaded on startup (`load_all_usage`) and written through on each
  `record_upload` (`record_usage`, which also prunes rows outside the 14d rolling
  window).
- Upload sessions: `Store::persist_session(id, &FileState)` writes one upsert, and
  it is called at each of the three transitions **before the handler responds** —
  `Store::create` (init), `upload_chunk` after the rolling token advances, and
  `upload_finalize` right after `sender` is set and before the email goes out. The
  reverse edges matter as much: `Store::remove` and the purge task both delete the
  row, so an unresumable session never leaves one behind (without that the table
  would grow without bound and a future restore would resurrect sessions the purge
  already killed). DB errors are logged, never propagated — persistence must not
  add a way for a healthy upload to fail.
- Three things about the `upload_sessions` schema that are not guessable:
  `recovery_token_hash` stores `sha256(recovery_token)` hex, never the plaintext
  bearer credential, and since #303 that is true of the *live* `FileState` too,
  so `upload_status` hashes the presented `X-Recovery-Token` and compares
  digests. A restored session and a fresh one hold exactly the same thing;
  `created_at` is deliberately absent from the upsert's `DO UPDATE SET` list, which
  is what keeps it recording when the session began; and there is **no
  expected-size column**, because clients send `Content-Range: bytes <s>-<e>/*` on
  chunk PUTs and the total is genuinely unknown to the server until finalize
  declares it (finalize then rejects a declaration that disagrees with `uploaded`).
- `email::Language::code()` (`"EN"`/`"NL"`) is what the `mail_lang` column stores,
  `Language::from_code` reads it back at restore, and two tests in `email.rs` hold
  the three forms together: `language_code_matches_serde_representation` pins
  `code()` to the serde/wire form, and `language_code_round_trips_through_from_code`
  pins the inverse and its rejection of anything else. A restored session can't
  come back with a `mailLang` no client would send, or in a language the sender
  never chose.

## api-description.yaml is tied to the mounted routes by a test
`api_routes()` in `src/main.rs` is the single mount list; `build_rocket` mounts it
and `mod api_description_tests` compares it against `api-description.yaml`. A new,
removed, or renamed route fails `cargo test` until the spec is updated too. The
test only checks method + path shape (placeholder *names* are ignored, so the
route's `<filename>` binding and the spec's `{uuid}` compare equal) — response
codes and schemas are still on you.

The spec is also the external contract for pg-js, pg-dotnet, and the add-ins, so
a breaking edit to it needs a new versioned route rather than an in-place change
(cryptify's routes are unversioned, so there is no other escape hatch).

## The oasdiff gate's settings, and the test that pins them

`.github/workflows/api-diff.yml` diffs the PR's `api-description.yaml` against
the base branch. Its whole behaviour is two step inputs, and a wrong pair fails
open: the job goes green and nobody learns the change went through. So
`mod api_gate_tests` in `src/main.rs` mutates the real spec one way per rule,
runs the real engine with the flags the action's entrypoint builds, and asserts
stop-or-pass. It also reads the committed workflow and asserts its two inputs
are the constants the module pins, and that the job still triggers on
`pull_request` with no path filter and no `if:` — settings on a gate that never
runs fail open just as quietly. So the two cannot drift apart unnoticed.

The settings the gate needs are `fail-on: WARN` plus
`include-checks: response-non-success-status-removed,response-property-enum-value-removed`.
**The committed workflow does not have them yet**: it is still `fail-on: ERR`
with no `include-checks`. The new pair sits in the `api-diff.yml` patch on
PR #203 and needs a maintainer to apply it, because the App cannot push
`.github/workflows/`. Until that lands, the gate is passing everything in the
list below, and `the_workflow_uses_the_settings_this_module_pins` is red saying
so. Tighten this paragraph back to plain present tense in that same PR once the
maintainer's commit is on the branch.

Measured on this spec against oasdiff v1.26.1, `fail-on: ERR` on its own passes
several changes the contract forbids. A `401` that becomes a `403` and a
dropped response enum value rate ERR but are opt-in, so they never run unless
named, which is what `include-checks` is for. The rest rate WARN, not ERR: a removed
or renamed optional response property, a removed request parameter, a removed
request property, and the constraint-narrowing `*-set` family. Those gaps are
spec-independent, so they apply here even though this spec marks most fields
`required` (which does make a removed *required* response property an ERR).

WARN adds 30 checks on top of ERR's 212 (`oasdiff checks -s warn -f json`; the
table output has two rows more than that, a header and a trailing blank). All
but one of the 30 are changes the contract
already forbids. The exception is `response-property-enum-value-added`: adding
a value to `UploadSessionNotFound.reason` or `PayloadTooLarge.limit` fails the
gate even though a wider response enum is additive on paper, and today's
consumers do tolerate it (pg-js reads `reason` as `parsed.reason ?? 'unknown'`,
a plain string, and the tb-addon passes it through). It is kept anyway: nothing
stops a future client from switching on those codes, and a red gate that asks
for a decision beats a silent pass. It is also the only rule here that WARN
alone enforces, so it is the first casualty of a revert to ERR, which is why
the test pins it.

Two things to know before reaching for a suppression. `--warn-ignore` and
`--err-ignore` do not take check ids or partial regexes: the ignore file is
matched by asking whether an ignore line *contains* the rendered change text,
so a line has to spell out the whole thing in lowercase, per affected
operation, including the new value:

```
in api put /fileupload/{uuid} added the new `quota_exceeded` enum value to the `reason` response property for the response status `404`
```

A bare `response-property-enum-value-added`, or even `.*`, suppresses nothing
(verified on v1.26.1). So there is no standing "ignore this check" setting;
every future enum value needs its own lines. And `x-extensible-enum` in place
of `enum:`, which oasdiff's own message suggests, makes it skip that property
altogether: adding a value passes, but so does *removing* one, so that trade
buys the false positive back with a gap.

The mutation test needs the engine, which no runner has, so it skips in CI. The
other two do run there: `every_api_gate_mutation_still_applies` catches a spec
edit that strands an anchor, and
`the_workflow_uses_the_settings_this_module_pins` catches the workflow and the
constants disagreeing. To run the mutation test for real:

```
go install github.com/oasdiff/oasdiff@v1.26.1   # the version the action tag pins
cargo test --all-targets api_gate
```

## Content-Range end byte is EXCLUSIVE on the chunk PUT
`upload_chunk` rejects `start >= end` and takes the chunk length to be
`end - start`, so `bytes 200-1000/*` is 800 bytes at offset 200, not the 801 that
RFC 7233 would mean. `postguard-js` (`src/api/cryptify.ts:storeChunk`) sends
`bytes <off>-<off+len>/*` to match — that is correct, not an off-by-one. Do not
"fix" it in either repo alone; both sides move together or neither does.

## Token chain must be checked on every route touching a FileState
The upload token chain (`SHA256(prev || chunk)`) must be validated on every route
that operates on an existing `FileState`, not just `PUT`. An earlier version only
checked it on `PUT`, letting anyone who guessed a live UUID finalize another user's
upload (fixed). When adding new routes, mirror the token check `upload_chunk` uses;
don't trust UUID knowledge alone as authorization.

## CORS
`allowed_origins` is a single regex string in `rocket_cors` 0.6.0.
`AllowedOrigins::some_regex` compiles via `regex::RegexSet`; standard alternation
works fine. The regex is anchored (`^...$`), so there's no subdomain/wildcard
bypass.

## Metrics
- `GET /metrics`: Prometheus text format, unauthenticated by design. Lock down at
  the firewall, not the endpoint.
- Channel label derived in priority: `X-Cryptify-Source`, then
  `Authorization: Bearer` / `X-Api-Key` (-> `api`), then `Origin` (-> `website` /
  `staging-website`), then `User-Agent` (-> `outlook` / `thunderbird`), then
  `unknown`. Sanitized to `[a-z0-9_-]`, max 32 chars.
- Storage gauges are sampled from `data_dir` on a background task (default 60s,
  `metrics_scan_interval_secs`).
- `FileState.source_channel` is populated at `upload_init` from request headers;
  populate it in any new test fixtures too.

## Integration test harness
- `build_rocket(figment, vk)` is the injection point. `#[launch] rocket()` wraps it
  and fetches vk via `minreq` for production.
- `CryptifyConfig.email_stub: bool` (default false) short-circuits `send_email`;
  set true in test figments.
- `pg_core::test::TestSetup` provides `VerifyingKey` plus an encryption policy and
  signing keys. The test policy includes `pbdf.sidn-pbdf.email.email =
  "bob@example.com"`; seal with `signing_keys[2]` (Bob) for finalize to succeed.
- pg-core's Sealer API uses rand 0.8; cryptify uses rand 0.9. Dev-deps alias
  `rand08 = { package = "rand", version = "0.8" }`; use `rand08::thread_rng()` only
  in test code calling pg-core directly.
- Integration tests live inline in `src/main.rs` under `mod integration`, not in
  `tests/` (that would require a library target).
- Each test gets a per-test temp `data_dir` under `std::env::temp_dir()` with a
  uuid suffix for parallel safety.

For handler-level tests that need `State<CryptifyConfig>` and `State<Store>`
without the full `build_rocket` injection point:

```rust
use rocket::figment::{providers::Serialized, Figment};
use rocket::local::asynchronous::Client;

let figment = Figment::from(rocket::Config::default()).merge(Serialized::defaults(
    serde_json::json!({
        "server_url": "http://localhost",
        "data_dir": data_dir.to_str().unwrap(),
        "email_from": "Test <test@example.com>",
        "smtp_url": "localhost",
        "smtp_port": 1025u16,
        "allowed_origins": ".*",
        "pkg_url": "http://localhost",
    }),
));

let rocket = rocket::custom(figment)
    .mount("/", routes![upload_init])
    .attach(AdHoc::config::<CryptifyConfig>())
    .manage(Store::new());
let client = Client::tracked(rocket).await.unwrap();
```

Gotchas: `#[rocket::async_test]` is required (Store spawns purge_task, needs a
reactor). `InitBody` is camelCase; send `mailContent` and `mailLang` (not
snake_case) or you get a 422. `email::Language` serializes uppercase (`"EN"`,
`"NL"`). This minimal harness only works for routes that don't need the verifying
key (`upload_init`, `health`, `usage`); routes needing vk need the full
`build_rocket(figment, vk)`.

## X-PostGuard header convention
Cryptify's notification emails set an `X-PostGuard` header using the `pg-core`
crate version as the value (e.g. `X-PostGuard: 0.6.1`), wired at build time via
`build.rs` reading `Cargo.lock`. This gives operational visibility into which
postguard version processed a given email, and it advances automatically as
`pg-core` is bumped, no manual updates needed. This supersedes an earlier
preference for a semantic token like `notification` (cryptify#170).

For reference, the tb-addon (Thunderbird) implementation sets
`x-postguard: 0.1.0` via `customHeaders` on `onBeforeSend`; detection of "is this a
PostGuard message" elsewhere uses the `postguard.encrypted` attachment or the
inline `-----BEGIN POSTGUARD MESSAGE-----` marker, not this header.
`X-PostGuard-Client-Version` is a separate, unrelated HTTP header sent on PKG
requests (not a MIME header on the email).

## Security: reviewed and confirmed clean, don't re-report
From the 2026-07-02 in-depth security audit (the one confirmed finding from that
audit, unauthenticated `/usage` enumeration, was fixed and merged in PR #183):
- **Path traversal on `GET /filedownload/<filename>`**: guarded by
  `is_safe_download_segment` (rejects empty, len>128, `/`, `\`, NUL, `.`, `..`).
  On-disk files are named by random UUIDv4, so the download key is an unguessable
  capability.
- **HTML injection / XSS in notification emails**: `mail_content` is
  attacker-controlled (init is unauthenticated) but rendered via Askama as
  `{{html_content}}` without `|safe`, so it's auto-HTML-escaped. The `.txt`
  template uses `escape="none"` correctly for plaintext.
- **Email header injection**: `recipient` is parsed via lettre `Mailboxes`;
  `reply_to` comes from the signed IRMA email attribute. lettre validates both.
- **Upload/finalize auth**: chunk PUT and finalize are gated by the rolling
  `cryptify_token` (`SHA256(prev||chunk)`); finalize checks it too. The status
  endpoint is gated by a constant-time `X-Recovery-Token` comparison, with
  401-vs-404 collapsed to avoid leaking session existence. Since #303 the
  comparison is digest-versus-digest: the server keeps only
  `sha256(recovery_token)`, so both comparands are fixed-length hex and there is
  no length to leak either.
- **Secrets in git history**: none; `conf/config.toml` and `config.dev.toml` only
  ever had commented-out placeholders.
- **`/metrics` unauthenticated**: known and by design, locked down at the
  firewall.
- **`/staging/preview/<uuid>`**: 404s unless `staging_mode` is on; safe in prod.

## Test-runner quirk

`Store` tests need a tokio runtime: use `#[rocket::async_test]` on `async fn`, even when the body never awaits.
