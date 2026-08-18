# Compatibility

What an external consumer of PostGuard can rely on: which HTTP endpoints stay
put, which stored ciphertexts stay readable, and which published SDK versions
are kept working against the current server and the current wire format.

Three seams are covered, each with its own guarantee.

## Hosted API

The `/v2` contract is [`pg-pkg/api-description.yaml`](pg-pkg/api-description.yaml).

Changes to `/v2` are additive only. New endpoints, new optional request fields
and new response fields are allowed, so a client written against an older
revision of the spec keeps working. These are not allowed on `/v2`: removing a
route or a field, renaming either, narrowing a type, making an optional field
required, changing the status code for a condition a client already handles, or
adding a value to a response enum, since a client that switches on `status`
without a default branch breaks on a value it has never seen.

A change that cannot be made additively ships under a new prefix (`/v3`), with
`/v2` left running until its consumers are gone.

`/v2/irma/...` is a legacy alias for the canonical `/v2/request/...`; both
prefixes serve the same handlers today. The alias is deprecated as of
2026-07-27. New clients should use `/v2/request/...`, and the alias will be
removed once the deprecation process at the bottom of this file has run for it
([#257]). Until then it keeps working, so a deployed client on `/v2/irma/...`
is not broken by this notice.

Enforcement: the `API breaking changes (oasdiff)` job in
`.github/workflows/api-diff.yml` diffs the spec against the branch a PR targets
and fails on any change oasdiff rates WARN or ERR ([#249]). That covers every
rule above except one. The gate compares documented paths, and this spec
documents the canonical `/v2/request/...` paths only, so dropping the
`/v2/irma/...` alias handlers before the deprecation above has run passes it;
that one stays a review rule. A `/v3` route added next to `/v2` reads as
additive, so the gate passes the escape hatch. `pg-pkg/tests/api_gate.rs` pins
which changes the gate stops and which it lets through; run it before changing
what the gate checks.

## Stored artifacts

Containers and envelopes stay readable. Once a release can open a format, no
later release drops that ability, and there is no expiry on it. A container
that cannot be opened fails with a typed error, never silently.

The guarantee starts at container format `VERSION_2` (bincode header,
[`pg-core/src/consts.rs`](pg-core/src/consts.rs)), which is the only format
current readers accept. `VERSION_0` (Kiltz-Vahlis-1) and `VERSION_1`
(MessagePack header) predate this document and were dropped before it;
`preamble_checked` rejects both with `Error::IncorrectVersion`. Each constant
is named after the wire value it holds; the older `VERSION_V1`/`VERSION_V2`/
`VERSION_V3` names, which counted from one, are deprecated aliases and go at
the next major.

Format changes roll out readers first. Read support ships in one release and
the write default flips a major later, so nothing gets written that the
installed base cannot open.

Email envelopes are the `@e4a/pg-js` layer and carry the same guarantee. Their
compat gate is live ([postguard-js#131]): the `envelope-compat` job, display
name `Envelope compatibility`, in [postguard-js]'s
`.github/workflows/integration.yml`. It is deliberately not path-filtered,
because a path-filtered required check reports nothing on the pull requests that
miss the filter, and `packages/pg-js/tests/ci-wiring.test.ts` asserts it still
runs both directions.

Envelope detection is covered by this section as well. Detection is how a
delivered message is recognised as PostGuard before anything is decrypted, so
the readers doing it are installed mail clients holding messages no later
release can reach. The `postguard.encrypted` attachment name is therefore kept
forever. Every message already in a mailbox is found by it, and dropping that
leg would cost read access to stored artifacts, which this section rules out.
So the deprecation process at the bottom of this file does not apply to it. A
detection leg added later inherits the same rule, and the set only grows
([#259]).

Enforcement today: `pg-core/tests/wire_format.rs` opens the committed golden
fixtures under `pg-core/testdata/wire-format-v3/` on every
`cargo test -p pg-core --features test,rust,stream`. Planned: the append-only
corpus in [postguard-e2e#19], one artifact per readable container format and
envelope tier, tested in both directions.

## SDK support windows

The window is the set of published SDK versions kept working against the
current server and the current wire format.

- `@e4a/pg-js` (npm): the last two majors. `1.x` leaves the window when
  telemetry shows no `1.x` traffic. The other half of that condition, the
  Outlook add-in's v1 → v2 migration, **has landed**: the add-in lives at
  `apps/outlook-addon` in [postguard-js] on `@e4a/pg-js": "workspace:*"` (2.x)
  and released as `outlook-addin-v1.0.0`. [postguard-outlook-addon#125] is
  closed and stayed in that now-archived repo, so treat it as a historical
  record rather than a tracker.
- `@e4a/pg-wasm` (npm): every version a supported `pg-js` resolves.
- `E4A.PostGuard` (NuGet): the last major. `0.x` counts as one line until
  `1.0`.
- `pg-core` (crates.io): the last two minors.

A version stays in the window for at least 12 months after its successor
ships, and longer while live client-version telemetry still shows it
([postguard-ops#64]).

Read support for stored artifacts is not part of this window. It never drops,
whatever happens to the SDK version that wrote the bytes.

No window is declared for `pg-cli` or `pg-ffi`. `pg-ffi` consumers pin an
exact release rather than building against the latest one
([postguard-dotnet#50]).

## Reader list

The window above resolved to concrete versions: the highest published patch of
each line in the window. This is the list the compat gates install and run as
readers. `wire-compat-js` enforces the npm rows
(`pg-compat-js/test/manifest.test.mjs` machine-reads the fenced block below,
so a drifted npm row goes red), and `wire-compat-rust` now enforces both
crates.io versions pinned in `pg-compat/Cargo.toml`
(`pg-compat/tests/support_window.rs` reads the same block and fails when it
drifts from `pg-compat`'s `readers()`) — keep that block as rows, not prose,
in either direction.

```
# <registry> <package> <versions...>
crates.io pg-core 0.6.3 0.5.10
npm @e4a/pg-wasm 0.6.1
npm @e4a/pg-js 2.3.3 1.11.0
nuget E4A.PostGuard 0.6.0
```

Checked against the registries on 2026-08-06. A producer publishing a new
version moves a pin; a line leaves the list only through the deprecation
process below. The npm version of `@e4a/pg-wasm` tracks the released `pg-core`
version rather than `pg-wasm/Cargo.toml`, so read that pin from npm and not
from the crate manifest.

Live consumers of this list, both in `.github/workflows/build.yml`:

- `wire-compat-rust` ([#260]): seals with HEAD and opens with the pinned
  published `pg-core`
- `wire-compat-js` ([#261]): opens the same bytes with the published npm readers

Neither is a required check on its own. [#262] replaced the two per-language
contexts with the single `wire-compat` job, whose display name **`Wire compat`**
is what both branch protection and the `main: required checks` ruleset pin — so
that name is load bearing, and `pg-core/tests/ci_wiring.rs` ([#272]) asserts it
still belongs to the job that aggregates both halves.

The envelope tiers have their own gate, the live `Envelope compatibility` job
described under Stored artifacts. Two further jobs were listed here as planned;
one has since landed:

- [postguard-e2e#25], the forward-direction fixture job, is still planned and
  its issue is still open.
- [postguard-e2e#21], the version sweep, landed as [postguard-e2e#41]. It runs
  nightly against edge from `.github/workflows/version-sweep.yml` in
  [postguard-e2e] and exposes a `pre-deploy` profile over `workflow_call`, for
  a deploy pipeline to call against candidate images. No pipeline calls it yet.

A gate that needs a different set of readers changes this file first. The two
npm lines are also spelled out in `pg-compat-js/src/readers.mjs`, whose
`test/manifest.test.mjs` parses the block above and fails when the two lists
drift, so keep that block as rows and not as prose.

Known coverage gap in the rows above, tracked in [#268]: the `nuget` row has no
gate. `E4A.PostGuard` is a producer-only SDK (seal via pg-ffi, no unseal path),
so a reader gate needs a decrypt capability the SDK does not have. Decided:
leave it declared-but-ungated here rather than build that capability into this
gate; the .NET seal direction is instead covered by [postguard-e2e#21]'s version
sweep, now in CI with decrypt legs, which owns driving published NuGet versions
against a target server.

## Deprecation

1. Announce. Say what is deprecated next to the item in the spec or in this
   file, with the date the clock starts. The next release of the affected
   component repeats it in its changelog entry. The date is what step 3 counts
   from, so an announcement without one does not start the window.
2. Observe. `pg-pkg` exports `postguard_clients{client,client_version,host,...}`
   per request, so the versions in the field are measurable. Scraping it is
   [postguard-ops#64]; while that is not running there is no field data, and
   nothing gets removed.
3. Remove. Only once the window has expired and telemetry shows no traffic for
   what is being removed.

Skipping step 2 is how you break the consumers you cannot see.

[#249]: https://github.com/encryption4all/postguard/issues/249
[#257]: https://github.com/encryption4all/postguard/issues/257
[#259]: https://github.com/encryption4all/postguard/issues/259
[#260]: https://github.com/encryption4all/postguard/issues/260
[#261]: https://github.com/encryption4all/postguard/issues/261
[#262]: https://github.com/encryption4all/postguard/issues/262
[#268]: https://github.com/encryption4all/postguard/issues/268
[#272]: https://github.com/encryption4all/postguard/issues/272
[postguard-js]: https://github.com/encryption4all/postguard-js
[postguard-js#131]: https://github.com/encryption4all/postguard-js/issues/131
[postguard-e2e]: https://github.com/encryption4all/postguard-e2e
[postguard-e2e#19]: https://github.com/encryption4all/postguard-e2e/issues/19
[postguard-e2e#21]: https://github.com/encryption4all/postguard-e2e/issues/21
[postguard-e2e#25]: https://github.com/encryption4all/postguard-e2e/issues/25
[postguard-e2e#41]: https://github.com/encryption4all/postguard-e2e/pull/41
[postguard-dotnet#50]: https://github.com/encryption4all/postguard-dotnet/issues/50
[postguard-outlook-addon#125]: https://github.com/encryption4all/postguard-outlook-addon/issues/125
[postguard-ops#64]: https://github.com/privacybydesign/postguard-ops/issues/64
