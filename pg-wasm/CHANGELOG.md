# Changelog

## How this package is versioned

`@e4a/pg-wasm` has no release cycle of its own. It is published to npm on
**every** `pg-core` release, at `pg-core`'s version: `delivery.yml`'s
`publish-wasm` job takes the version straight from the `pg-core` release and
publishes. There is no `pg-wasm` tag series, and there are deliberately no
per-version entries in this file.

**For what changed in any version of `@e4a/pg-wasm`, read
[`pg-core`'s changelog](../pg-core/CHANGELOG.md) for the same version number.**
That is the whole record for the shared surface; duplicating it here would only
create a second thing to keep true.

`pg-wasm/Cargo.toml`'s `version` field is *not* the published version — it is
unused by the npm publish path, which is why it reads `0.5.5` while npm serves
much later versions. The premise that the published version is `pg-core`'s is
pinned by `the_wasm_publish_still_takes_its_version_from_pg_core` in
`pg-core/tests/ci_wiring.rs`: if that derivation ever changes, this document
becomes wrong and that test goes red.

## Changes specific to pg-wasm

Only changes to the binding layer itself are listed here — everything else is in
`pg-core`'s changelog. Over the package's whole history these are all of them:

- **0.6.5** — the pre-decrypt sender identity is claimed, not verified
  ([#376](https://github.com/encryption4all/postguard/pull/376))
- **0.6.2** — omit the default module path in the `web` `wasm-bindgen` glue
  ([#222](https://github.com/encryption4all/postguard/pull/222))

## Notes

- `0.5.6` was tagged as `pg-core-v0.5.6` but was **never published to npm**; the
  registry jumps from `0.5.5` to `0.5.7`.

## [Unreleased]

## [0.5.5](https://github.com/encryption4all/postguard/releases/tag/pg-wasm-v0.5.5) - 2026-04-02

### Added

- release pg-wasm 0.3.0
- release pg-wasm 0.3.0-rc4
- update README.md
- expose the verified public identity
- add initial typescript declarations
- prerelease wasm package
- simplify return type of unseal

### Fixed

- replace wildcard dependency versions with concrete ranges
- wasm tests in the browser
- correct the generated types
- use camelCase in exported SealOptions

### Other

- bump wasm to 0.5.5
- Bump pg-wasm version to 0.5.3
- Upgrade wasm to 0.5.2
- cargo fmt
- Merge remote-tracking branch 'origin/main' into fix/pg-wasm-seal-options-types
- Upgrade wasm to 0.5.1
- pg-wasm to v0.5.0
- Fix deprecated web-sys API calls and boxed slice iterator warning
- Fixed missing doc error
- Fixed local build by updating to latest packages
- Remove attribute values for signing ([#32](https://github.com/encryption4all/postguard/pull/32))
- update README.md for pg-wasm
- 0.3.0 rc.0 ([#20](https://github.com/encryption4all/postguard/pull/20))
