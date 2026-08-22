# postguard

The root of the PostGuard family: identity-based encryption, where a sender needs
only the recipient's identity (an email address, a phone number) plus the PKG's
master public key, and the recipient proves that identity to the PKG to get a
decryption key. A Rust workspace. The README states the position plainly: *"All
other PostGuard tools and SDKs depend on this."*

## Parts

- `pg-core` — the IBE library: encryption metadata, key and ciphertext
  serialization, a streaming interface with a WASM backend.
- `pg-pkg` — the Private Key Generator, an actix-web HTTP server.
- `pg-wasm`, `pg-cli`, `pg-ffi` — the WebAssembly bindings, the command-line
  tool, the C ABI.
- `cryptify/` — file storage and delivery, folded in from the archived
  `cryptify` repo.
- `pg-compat`, `pg-compat-js` — the wire-compatibility gate: bytes sealed by
  this tree, opened by published readers.

`pg-wasm` and `pg-compat` are on the root `Cargo.toml`'s `exclude` list, so a
cargo command run from the root does not reach them.

## What a change here reaches

- A wire-format or `/v2` change reaches `postguard-js`, `postguard-dotnet`,
  `postguard-business` and `postguard-e2e` at once. `COMPATIBILITY.md` holds
  what those consumers may rely on (`/v2` stability, the archival read
  guarantee, the SDK support windows, the deprecation process) and is the
  document such a change has to argue against, not a formality.
- The edge to `postguard-js` runs through npm, not the repo: `@e4a/pg-js`
  depends on `@e4a/pg-wasm` by version range, so a core change lands in JS only
  on a release.
- The PKG does not verify identity itself. It starts a session against a **Yivi
  server** and issues the key on the disclosure result, so a Yivi disclosure
  change can break PostGuard decryption and nothing in either repo's tests will
  say so.

## One company, two orgs

`encryption4all` and `privacybydesign` are the same company, the same
maintainers, the same review conventions. `privacybydesign` is the Yivi/IRMA
lineage; `encryption4all` is the vehicle the PostGuard research project used to
apply for grants, kept as an org after Yivi bought PostGuard to commercialise
it. The split is historical, not organisational, and we are maintainers on every
repo in both.

## Where the operational knowledge is

Not in this file. Documentation lives at
[docs.postguard.eu/repos/postguard](https://docs.postguard.eu/repos/postguard).
A durable check is a rule, filed once and delivered to the next container at
`~/dobby-rules.md`. A trap tied to one file is a comment beside it:
`pg-core/tests/ci_wiring.rs`, `pg-pkg/tests/api_gate.rs`,
`pg-pkg/tests/dockerfile_workspace_members.rs` and `scripts/semver-checks.sh`
are written to be read before they are edited.

The corpus this file used to be is in git history: 67,118 bytes at `af6116c`,
the last revision carrying it (`git show af6116c:CLAUDE.md`). Anything else in
this repo that sends a reader to `CLAUDE.md` for a convention or a trap — the
escape hatch in `scripts/ruleset-drift.sh`, the local-repro command in
`.github/workflows/api-diff.yml`, the enum-gate reasoning in
`cryptify/src/main.rs` — means that revision and not this file.
`cryptify/CLAUDE.md` is a second corpus of the same kind and this change does
not touch it. A test in `pg-core` holds this file to 4,000 bytes.
