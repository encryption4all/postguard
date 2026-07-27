# pg-compat

Reader half of the Rust wire-compat gate ([#260], part of [#251] / epic [#247]).

`pg-core` seals a deterministic sample set with the code in this tree; this
crate opens that set with **published** `pg-core` releases from crates.io. A
red run means a wire change is not additive: containers produced after it ships
would be unreadable by SDKs already pinned by external consumers.

This crate is deliberately outside the workspace (the root `Cargo.toml` lists it
under `exclude`) so that `pg-core` resolves from crates.io rather than from
`../pg-core`. It keeps its own `Cargo.lock`; CI runs it with `--locked`.

## Running it

```sh
# 1. seal the sample set with HEAD
cargo run -p pg-core --features stream --example seal-samples -- target/wire-compat/artifacts

# 2. open it with every published reader in the support window
PG_COMPAT_ARTIFACTS="$PWD/target/wire-compat/artifacts" \
  cargo test --manifest-path pg-compat/Cargo.toml --locked
```

`PG_COMPAT_ARTIFACTS` defaults to `target/wire-compat/artifacts` relative to the
repo root. A missing or empty set is a failure, not a skip.

## Adding a version to the support window

The list of published readers is the support window declared in [#252]; the
manifest here and that document are meant to be the same list. Adding one is two
lines:

1. `pg-compat/Cargo.toml`: `pg-core-0-6-2 = { package = "pg-core", version = "=0.6.2", features = ["stream"] }`
2. `pg-compat/src/lib.rs`: `reader!(v0_6_2, pg_core_0_6_2, "0.6.2");` plus an
   entry in `readers()`.

Each version is a separate crate with separate types, which is why the check
body is a macro instantiated per version rather than a generic function.

## Artifact layout

The sealer writes a flat directory. Nothing in it is committed and nothing is
version-controlled: it is regenerated from HEAD on every run. The Node half of
the gate ([#261]) consumes the same directory as a job artifact, so this layout
is a contract: change it together with both readers and bump `schemaVersion`.

```
manifest.json                  index of the set (see below)
vk.json                        PKG parameters holding the verifying key
usk-alice.json                 user secret key for recipient "alice"
usk-bob.json                   user secret key for recipient "bob"
mem.bin                        sealed container
mem.plain                      bytes a reader must recover from mem.bin
mem-privsig.bin/.plain
stream.bin/.plain
stream-multi-segment.bin/.plain
```

`manifest.json`:

```json
{
  "schemaVersion": 1,
  "sealedBy": { "crate": "pg-core", "version": "0.6.1" },
  "wireVersion": 2,
  "verifyingKey": "vk.json",
  "sender": {
    "public": { "ts": 1704067200, "con": [{ "t": "...", "v": "..." }] },
    "private": { "ts": 1704067200, "con": [{ "t": "...", "v": "..." }] }
  },
  "cases": [
    {
      "name": "mem",
      "mode": "memory",
      "ciphertext": "mem.bin",
      "plaintext": "mem.plain",
      "privateSigning": false,
      "recipients": [
        { "id": "alice", "usk": "usk-alice.json" },
        { "id": "bob", "usk": "usk-bob.json" }
      ]
    }
  ]
}
```

- `schemaVersion`: layout of the manifest. A reader that does not recognise the
  value must fail, not skip. A gate that reads nothing and passes is worse than
  no gate.
- `wireVersion`: the container version the bytes claim (`VERSION_V3`, `2`).
- `mode`: `"memory"` for `Sealer<_, SealerMemoryConfig>::seal` (what pg-js
  `toBytes` produces), `"stream"` for the segmented container (what cryptify
  stores and pg-js uploads).
- `privateSigning`: the payload signature uses a separate, encrypted signing
  policy. A reader must report exactly this: the private claims present when it
  is `true`, absent when it is `false`.
- `recipients`: every recipient the container was sealed for. Each case must
  open with *each* recipient's key, which is what exercises the multi-recipient
  KEM entries in the header.
- `vk.json` and `usk-*.json` are shaped like real PKG responses
  (`{"formatVersion":0,"publicKey":"..."}` and
  `{"status":"DONE","proofStatus":"VALID","key":"..."}`), so the same files feed
  a Rust reader and a JS one without translation.
- The plaintext is a sibling file rather than base64 inside the manifest,
  because `stream-multi-segment.plain` is 260 KiB.

### Cases

| name | mode | covers |
| --- | --- | --- |
| `mem` | memory | the in-memory container, public header signature only |
| `mem-privsig` | memory | payload signed under an encrypted private policy |
| `stream` | stream | the segmented container, single segment |
| `stream-multi-segment` | stream | two segments: STREAM counter, final-segment flag, and a populated `size_hint` in the header |

### Determinism

The whole set is a pure function of one seed
(`pg-core/examples/seal-samples/sample_set.rs`), so two runs of the same tree
produce byte-identical files and a diff between two runs is a wire change rather
than RNG noise. The manifest deliberately carries no timestamp or commit hash
for the same reason; CI records which commit sealed a set in the uploaded
artifact's name. `pg-core/tests/sample_sealer.rs` holds the sealer to that.

### What "additive" turns out to mean here

Read a green run carefully. The header is a length-prefixed region and `bincode`
ignores trailing bytes, so a field appended at the *end* of `Header` really does
still open with 0.6.1. A field inserted anywhere else, a changed field type, or
a reordering shifts every following byte and fails immediately. The gate reports every case at once, so the failure
list tells you whether the break is in the header, the payload, or one mode
only.

[#247]: https://github.com/encryption4all/postguard/issues/247
[#251]: https://github.com/encryption4all/postguard/issues/251
[#252]: https://github.com/encryption4all/postguard/issues/252
[#260]: https://github.com/encryption4all/postguard/issues/260
[#261]: https://github.com/encryption4all/postguard/issues/261
