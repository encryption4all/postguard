# Contributing

## The wire-compat gate

A PR that touches the wire surface (`pg-core`, `pg-wasm`, `pg-compat`,
`pg-compat-js`, the root `Cargo.lock`/`Cargo.toml`, or this repo's workflow
files) is checked against every published reader in the support window
declared in [COMPATIBILITY.md](./COMPATIBILITY.md#reader-list): HEAD seals a
sample container set, and the pinned published `pg-core`/`pg-wasm`/`pg-js`
readers must still open it.

`wire-compat` is the single required status on the PR, consolidating the
Rust half (`wire-compat-rust`) and the JS half (`wire-compat-js`) in
[`.github/workflows/build.yml`](./.github/workflows/build.yml). Either half
failing turns it red.

**If it goes red, the fix is one of two things — never override the gate:**

- Make the change genuinely additive, so old readers still parse the new
  bytes (appending a field at the end of a length-prefixed struct is
  additive; inserting a field, changing a type, or reordering is not — see
  the wire-format note in root `CLAUDE.md`).
- If the change can't be additive, it's a new format. Ship read support for
  it a release ahead of flipping the write default, so nothing gets written
  that the installed base can't open yet (COMPATIBILITY.md's "Stored
  artifacts" section is the guarantee this protects).

Run the gate locally before pushing a wire-surface change:
`cargo run -p pg-core --features stream --example seal-samples -- <dir>`,
then follow `pg-compat/README.md` and `pg-compat-js`'s test setup to open the
result with the pinned readers.
