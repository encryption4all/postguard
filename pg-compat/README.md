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

The test opens each case in a child process, the `pg-compat-case` binary this
crate also builds. That is not tidiness: a published reader handed a shifted
header does not always return an error, it can read a garbage length prefix and
abort on the allocation. In one process that would take every remaining case
with it, and an abort is not a panic, so `catch_unwind` cannot hold it. To open
a single case by hand:

```sh
cargo run --manifest-path pg-compat/Cargo.toml --locked --bin pg-compat-case -- \
  "$PWD/target/wire-compat/artifacts" 0.6.1 mem
```

## Adding a version to the support window

The list of published readers is the support window declared in [#252]; the
manifest here and that document are meant to be the same list. Adding one is two
lines:

1. `pg-compat/Cargo.toml`: `pg-core-0-6-2 = { package = "pg-core", version = "=0.6.2", features = ["stream"] }`
2. `pg-compat/src/lib.rs`: `reader!(v0_6_2, pg_core_0_6_2, "0.6.2");` plus an
   entry in `readers()`.

Each version is a separate crate with separate types, which is why the check
body is a macro instantiated per version rather than a generic function.

`tests/support_window.rs` parses the `crates.io` row(s) out of
`COMPATIBILITY.md`'s `Reader list` block and asserts they match `readers()`, so
a version added to one and not the other goes red instead of drifting silently
([#268]). Update the document's fenced block in the same change.

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
stream-privsig.bin/.plain
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
- `sealedBy`: which crate at which version produced the set. Informational: it
  is the *writer*, so it is never the version a reader should check itself
  against. Use `wireVersion` for that.
- `wireVersion`: the container version the bytes claim (`VERSION_V3`, `2`).
- `sender.public`: the policy the sender signed the *header* with, visible to
  anyone who has the bytes. This is what a reader checks the header signature
  against, so a JS reader needs it as much as a Rust one.
- `sender.private`: the policy the sender signed the *payload* with in the
  `*-privsig` cases. Despite the name it is not a secret key; it is the claims a
  reader may only see after decrypting. It is present in the manifest for every
  set, but only the cases with `privateSigning: true` were sealed with it, so
  check it against `privateSigning` rather than against the case list.
- `mode`: `"memory"` for `Sealer<_, SealerMemoryConfig>::seal` (what pg-wasm's
  `seal()` produces), `"stream"` for the segmented container (what cryptify
  stores). pg-js is stream mode in both directions — `toBytes()` seals with
  `sealStream` and its decrypt path only has a `StreamUnsealer` — so the
  memory-mode cases are reachable from JS through pg-wasm alone.
- `privateSigning`: the payload signature uses a separate, encrypted signing
  policy. A reader must report exactly this: the private claims present when it
  is `true`, absent when it is `false` — unless it is a reader that cannot
  surface a private policy at all, which pg-js 1.x is; see
  [`pg-compat-js/README.md`](../pg-compat-js/README.md).
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
| `stream-privsig` | stream | payload signed under an encrypted private policy, which in stream mode lands in the payload trailer rather than the header |
| `stream-multi-segment` | stream | two segments: STREAM counter, final-segment flag, and a populated `size_hint` in the header |

### Consuming the set from another job

The `wire-compat-rust` job seals and uploads only when the PR touches the wire
surface; on every other PR it reports success with no artifact attached. A
`wire-compat-js` job with `needs: wire-compat-rust` that downloads
`wire-compat-artifacts-${{ github.event.pull_request.head.sha || github.sha }}`
unconditionally would therefore hard-fail on unrelated PRs rather than
skipping. The `wire-compat-js` job for `pg-compat-js` ([#261]) gates every
expensive step on
`needs.wire-compat-rust.outputs.sealed == 'success'`, the seal step's own
outcome, published by the job that owns it. Re-running the path filter in the
second job would leave two copies of it that have to agree forever, and the run
where they stop agreeing is one that downloads an artifact nobody produced. The
job still always reports, which is what a required check needs.

### Determinism

The whole set is a pure function of one seed
(`pg-core/examples/seal-samples/sample_set.rs`), so two runs of the same tree
produce byte-identical files and a diff between two runs is a wire change rather
than RNG noise. The policy timestamps in `sender` are a fixed constant, not a
clock, and the manifest deliberately carries no wall-clock timestamp or commit
hash for the same reason; CI records which commit sealed a set in the uploaded
artifact's name. `pg-core/tests/sample_sealer.rs` holds the sealer to that.

### What "additive" turns out to mean here

Read a green run carefully. The header is a length-prefixed region and `bincode`
ignores trailing bytes, so a field appended at the *end* of `Header` really does
still open with 0.6.1. A field inserted anywhere else, a changed field type, or
a reordering shifts every following byte and the set stops opening.

How it stops opening is worth knowing, because it is not a decode error. The
shifted bytes make 0.6.1 read a garbage length prefix and attempt a
multi-gigabyte allocation, which aborts the process rather than returning
`Err`. That is why each case runs in its own child: the gate reports the
aborted case by name and carries on with the rest, so the failure list still
tells you whether the break is in the header, the payload, or one mode only.
Expect lines like:

```text
pg-core 0.6.1: mem: reader died on signal 6 before it could report: memory allocation of 21474836480 bytes failed
```

A `VERSION_V3` bump is the one break reported before any ciphertext is touched,
once per reader rather than once per case.

[#247]: https://github.com/encryption4all/postguard/issues/247
[#251]: https://github.com/encryption4all/postguard/issues/251
[#252]: https://github.com/encryption4all/postguard/issues/252
[#260]: https://github.com/encryption4all/postguard/issues/260
[#261]: https://github.com/encryption4all/postguard/issues/261
[#268]: https://github.com/encryption4all/postguard/issues/268
