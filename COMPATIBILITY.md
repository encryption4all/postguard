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
required, or changing the status code for a condition a client already handles.

A change that cannot be made additively ships under a new prefix (`/v3`), with
`/v2` left running until its consumers are gone.

`/v2/irma/...` is a legacy alias for the canonical `/v2/request/...`; both
prefixes serve the same handlers today. The alias is deprecated as of
2026-07-27. New clients should use `/v2/request/...`, and the alias will be
removed once the deprecation process at the bottom of this file has run for it
([#257]). Until then it keeps working, so a deployed client on `/v2/irma/...`
is not broken by this notice.

Planned enforcement: an oasdiff gate that diffs the spec against `main` and
fails on a breaking change ([#249]). Until that lands, this is a review rule.

## Stored artifacts

Containers and envelopes stay readable. Once a release can open a format, no
later release drops that ability, and there is no expiry on it. A container
that cannot be opened fails with a typed error, never silently.

The guarantee starts at container format `VERSION_V3` (wire value `2`, bincode
header, [`pg-core/src/consts.rs`](pg-core/src/consts.rs)), which is the only
format current readers accept. `VERSION_V1` (Kiltz-Vahlis-1) and `VERSION_V2`
(MessagePack header) predate this document and were dropped before it;
`preamble_checked` rejects both with `Error::IncorrectVersion`.

Format changes roll out readers first. Read support ships in one release and
the write default flips a major later, so nothing gets written that the
installed base cannot open.

Email envelopes are the `@e4a/pg-js` layer and carry the same guarantee; their
compat gate is planned in [postguard-js#131].

Enforcement today: `pg-core/tests/wire_format.rs` opens the committed golden
fixtures under `pg-core/testdata/wire-format-v3/` on every
`cargo test -p pg-core --features test,rust,stream`. Planned: the append-only
corpus in [postguard-e2e#19], one artifact per readable container format and
envelope tier, tested in both directions.

## SDK support windows

The window is the set of published SDK versions kept working against the
current server and the current wire format.

- `@e4a/pg-js` (npm): the last two majors. `1.x` leaves the window when the
  Outlook migration lands ([postguard-outlook-addon#125]) and telemetry shows
  no `1.x` traffic.
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
each line in the window. This is the list the compat gates will install and run
as readers. None of those gates runs yet, so for now this list is a review rule
like the `/v2` one above.

```
# <registry> <package> <versions...>
crates.io pg-core 0.6.1 0.5.10
npm @e4a/pg-wasm 0.6.1
npm @e4a/pg-js 2.3.3 1.11.0
nuget E4A.PostGuard 0.6.0
```

Checked against the registries on 2026-07-27. A producer publishing a new
version moves a pin; a line leaves the list only through the deprecation
process below. The npm version of `@e4a/pg-wasm` tracks the released `pg-core`
version rather than `pg-wasm/Cargo.toml`, so read that pin from npm and not
from the crate manifest.

Planned consumers of this list, each still an open issue:

- [#251], the wire-compat gate as a required PR check, with the Rust half in
  [#260] and the Node half in [#261]
- [postguard-e2e#25], the forward-direction fixture job
- [postguard-e2e#21], the version sweep, to run nightly and pre-deploy
- [postguard-js#131], the envelope-compat gate

A gate that needs a different set of readers changes this file first. The two
npm lines are also spelled out in `pg-compat-js/src/readers.mjs`, whose
`test/manifest.test.mjs` parses the block above and fails when the two lists
drift, so keep that block as rows and not as prose. On the `crates.io` line only
`0.6.1` is spelled out in `pg-compat/Cargo.toml`; `0.5.10` is declared here and
opened by no gate.

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
[#251]: https://github.com/encryption4all/postguard/issues/251
[#257]: https://github.com/encryption4all/postguard/issues/257
[#260]: https://github.com/encryption4all/postguard/issues/260
[#261]: https://github.com/encryption4all/postguard/issues/261
[postguard-js#131]: https://github.com/encryption4all/postguard-js/issues/131
[postguard-e2e#19]: https://github.com/encryption4all/postguard-e2e/issues/19
[postguard-e2e#21]: https://github.com/encryption4all/postguard-e2e/issues/21
[postguard-e2e#25]: https://github.com/encryption4all/postguard-e2e/issues/25
[postguard-dotnet#50]: https://github.com/encryption4all/postguard-dotnet/issues/50
[postguard-outlook-addon#125]: https://github.com/encryption4all/postguard-outlook-addon/issues/125
[postguard-ops#64]: https://github.com/privacybydesign/postguard-ops/issues/64
