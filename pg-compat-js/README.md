# pg-compat-js

Node half of the wire-compat gate ([#261], part of [#251] / epic [#247]).

`pg-core` seals a deterministic sample set with the code in this tree; this
package opens that set with the **published** npm readers in the support window.
A red run means a wire change is not additive: containers produced after it
ships would be unreadable by the SDK versions external consumers are already
pinned to.

The Rust half is [`pg-compat`](../pg-compat), which does the same with published
`pg-core` releases and documents the artifact layout the two halves share.

## Running it

```sh
# 1. seal the sample set with HEAD (the Rust half's sealer)
cargo run -p pg-core --features stream --example seal-samples -- target/wire-compat/artifacts

# 2. open it with every published JS reader in the support window
npm --prefix pg-compat-js ci
PG_COMPAT_ARTIFACTS="$PWD/target/wire-compat/artifacts" npm --prefix pg-compat-js test
```

`PG_COMPAT_ARTIFACTS` defaults to `target/wire-compat/artifacts` relative to the
repo root, the same default `pg-compat` uses, so one sealed set feeds both
halves. A missing or empty set is a failure, not a skip.

In CI the set arrives as the `wire-compat-artifacts-<sha>` artifact the
`wire-compat-rust` job uploads rather than being sealed again, so the two halves
are held to the same bytes.

Each case is opened in a child process, `bin/pg-compat-case.mjs`, for the reason
the Rust half does it: a reader handed a shifted header does not always return
an error, it can read a garbage length prefix and die on the allocation. To open
a single case by hand:

```sh
node pg-compat-js/bin/pg-compat-case.mjs \
  "$PWD/target/wire-compat/artifacts" '@e4a/pg-wasm@0.6.1' mem
```

`npm test` runs three things besides the gate itself: the reporting logic
(`test/failures.test.mjs`), the refusals that stop a set this reader does not
understand from passing quietly (`test/manifest.test.mjs`), and a self-test that
hands the readers a damaged copy of the set and requires a failure naming the
case (`test/gate-teeth.test.mjs`). The last one is what catches a harness that
has stopped reading. The gate asserting that good bytes open is an assertion a
broken harness also satisfies.

## The readers

| reader | opens | notes |
| --- | --- | --- |
| `@e4a/pg-wasm` 0.6.1 | every case | both unsealers, so the only reader that covers memory mode |
| `@e4a/pg-js` 2.3.3 | the `stream*` cases | through `PostGuard#open`, the path consumers use |
| `@e4a/pg-js` 1.11.0 | the `stream*` cases | same, one major back |

Two things about that table are worth knowing before reading a green run.

`pg-js` is stream-mode only, in both directions. Its decrypt path goes through
`StreamUnsealer` whichever input mode it is given, so a memory-mode container
comes back as `mode is not supported: InMemory { size: N }` — a typed refusal,
not a wire break — and it does not write one either (`toBytes()` seals with
`sealStream`). The memory-mode cases are therefore the `pg-wasm` reader's alone,
and the gate prints which reader opened which case so that stays visible.

`pg-js` 1.11.0 never reports a private signing policy. It throws away what
`StreamUnsealer.unseal()` returns and reports `public_identity()` instead, which
only sees the header; 2.x keeps the unseal result. That is a fixed SDK
limitation rather than something the wire format can change, so the reader
declares it and the gate then requires the private policy to be *absent* for
that reader. A 1.x that suddenly reported one would be a mismatch, not a quiet
pass.

Nothing else is excluded. Every case must be opened by at least one reader and
every reader must open at least one case, or the gate fails: a check that reads
nothing is worse than no check.

## Adding a version to the support window

The list of published readers is the support window declared in
[`COMPATIBILITY.md`](../COMPATIBILITY.md); `src/readers.mjs` and that document
are meant to be the same list. `test/manifest.test.mjs` parses the `Reader list`
block in that document and fails when the two drift, so the document is where a
version lands first:

1. [`COMPATIBILITY.md`](../COMPATIBILITY.md): the version on that package's `npm`
   row in the `Reader list` block. It decides; the rest of this list is the gate
   catching up.
2. `package.json`: `"pg-js-2-4-0": "npm:@e4a/pg-js@2.4.0"`. An alias, because
   several versions of one package have to coexist in one `node_modules`.
3. `src/readers.mjs`: one more entry in `readers()`.
4. `npm install`, and commit the lockfile it moves. CI installs with `npm ci`.

Steps 2 and 3 name the version twice, so the entry's `version` is also compared
against the one npm resolved the alias to: a typo in either place is a red run
rather than a gate that runs one version and labels it another.

Set `wireVersion` on the entry when the reader speaks a container version other
than `VERSION_V3`. Unlike the Rust half, which reads the constant out of the
published crate, nothing on the JS side exports it, so it is declared here.

## Why there is a PKG stub

`pg-js` is an SDK for a deployment: give it a `pkgUrl` and it fetches the
verifying key and the recipient's user secret key, because in the field the USK
only exists after a Yivi disclosure. The gate has neither a PKG nor a Yivi app,
but the sealer writes both keys shaped like the responses of the two endpoints
the decrypt path calls, so `src/readers/pkg-stub.mjs` serves those two files and
nothing else. Where a browser consumer passes `element` and scans a QR code, the
gate passes a session callback that hands the stub a recipient id in place of a
JWT. Everything after that is the published SDK's own code.

The alternative, stubbing the unsealer instead, would test the stub.

[#247]: https://github.com/encryption4all/postguard/issues/247
[#251]: https://github.com/encryption4all/postguard/issues/251
[#261]: https://github.com/encryption4all/postguard/issues/261
