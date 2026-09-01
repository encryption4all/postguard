# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.4](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.6.3...pg-pkg-v0.6.4) - 2026-09-01

### Added

- *(pg-pkg)* count every /v2 request in postguard_clients and bound its labels ([#384](https://github.com/encryption4all/postguard/pull/384))

### Fixed

- *(pg-pkg)* give each client its own client_version budget ([#390](https://github.com/encryption4all/postguard/pull/390))

## [0.6.3](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.6.2...pg-pkg-v0.6.3) - 2026-08-24

### Other

- updated the following local packages: pg-core

## [0.6.2](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.6.1...pg-pkg-v0.6.2) - 2026-08-18

### Added

- *(pg-core)* canonicalize identity attribute values before deriving ([#335](https://github.com/encryption4all/postguard/pull/335))

### Fixed

- *(cryptify)* build dev.Dockerfile from the repo root, like its sibling ([#329](https://github.com/encryption4all/postguard/pull/329))

### Other

- guard the Dockerfile/workspace-member invariant, scope the dev cook ([#326](https://github.com/encryption4all/postguard/pull/326))

## [0.6.1](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.6.0...pg-pkg-v0.6.1) - 2026-08-10

### Added

- *(cryptify)* merge cryptify into the workspace ([#277](https://github.com/encryption4all/postguard/pull/277))

## [0.6.0](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.5.11...pg-pkg-v0.6.0) - 2026-07-30

### Added

- *(pkg)* configurable email attribute type for API-key signing identities ([#244](https://github.com/encryption4all/postguard/pull/244))
- *(api)* pin the v2 HTTP contract and reject unknown request fields ([#242](https://github.com/encryption4all/postguard/pull/242))
- *(pkg)* proxy IRMA /statusevents SSE endpoint ([#200](https://github.com/encryption4all/postguard/pull/200))
- *(api)* accept Yivi condiscon in IrmaAuthRequest ([#198](https://github.com/encryption4all/postguard/pull/198))

### Fixed

- *(pkg)* refresh the IRMA JWT verification key on signature mismatch ([#241](https://github.com/encryption4all/postguard/pull/241))
- *(pkg)* fetch the IRMA JWT verification key lazily instead of at startup ([#240](https://github.com/encryption4all/postguard/pull/240))
- *(pg-pkg)* rate-limit on real client IP (X-Forwarded-For) behind a trusted proxy ([#230](https://github.com/encryption4all/postguard/pull/230))
- *(pg-pkg)* add per-IP rate limiting to /v2 API endpoints ([#224](https://github.com/encryption4all/postguard/pull/224)) ([#226](https://github.com/encryption4all/postguard/pull/226))
- *(pg-pkg)* validate session token path param before upstream URL ([#225](https://github.com/encryption4all/postguard/pull/225))
- *(pg-pkg)* mask internal error details in HTTP responses ([#221](https://github.com/encryption4all/postguard/pull/221))
- *(pg-pkg)* [**breaking**] require explicit --allowed-origins for CORS ([#216](https://github.com/encryption4all/postguard/pull/216)) ([#219](https://github.com/encryption4all/postguard/pull/219))

### Other

- breaking-change gate on the pg-pkg OpenAPI contract (oasdiff) ([#269](https://github.com/encryption4all/postguard/pull/269))
- clear clippy warning backlog for the clippy CI job ([#193](https://github.com/encryption4all/postguard/pull/193)) ([#229](https://github.com/encryption4all/postguard/pull/229))
- bump reqwest 0.12 → 0.13 and inquire 0.6 → 0.9 ([#196](https://github.com/encryption4all/postguard/pull/196))
- consume irmars from crates.io and bump reqwest to 0.12 ([#192](https://github.com/encryption4all/postguard/pull/192))
- bump bincode-next 3.0.0-rc.13 to 3.0.0-rc.14 ([#191](https://github.com/encryption4all/postguard/pull/191))
- address cargo audit advisories

## [0.5.11](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.5.10...pg-pkg-v0.5.11) - 2026-05-16

### Added

- *(pg-pkg)* add /v2/api-key/validate endpoint

### Fixed

- *(pg-pkg)* redact attribute values from USK debug log
- *(pg-pkg)* use &str slice for prometheus label values

### Other

- refresh deps and bump criterion / indicatif / qrcode / twox-hash
- migrate from bincode 1.3.3 to bincode-next 3.0.0-rc.13
- update dependencies
- Merge pull request #164 from encryption4all/fix/pg-pkg-bincode-unwrap-159
- Merge remote-tracking branch 'origin/main' into fix/pkg-hardening-139
- Merge pull request #163 from encryption4all/fix/lazy-static-to-lazylock
- replace lazy_static with std::sync::LazyLock

## [0.5.10](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.5.9...pg-pkg-v0.5.10) - 2026-04-25

### Other

- Merge pull request #149 from encryption4all/fix/pkg-cors-allowlist

## [0.5.9](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.5.8...pg-pkg-v0.5.9) - 2026-04-24

### Added

- *(pg-pkg)* validate API keys against postguard-business schema ([#140](https://github.com/encryption4all/postguard/pull/140))

### Fixed

- align API key query with latest business schema
- correct typos and outdated references in READMEs

### Other

- *(pg-pkg)* apply cargo fmt

## [0.5.8](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.5.7...pg-pkg-v0.5.8) - 2026-04-10

### Added

- support optional attributes in Yivi disclosure sessions

## [0.5.7](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.5.6...pg-pkg-v0.5.7) - 2026-04-03

### Other

- update Cargo.lock dependencies

## [0.3.2](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.3.1...pg-pkg-v0.3.2) - 2026-04-03

### Other

- add categories to pg-pkg, improve pg-core description

## [0.3.1](https://github.com/encryption4all/postguard/compare/pg-pkg-v0.3.0...pg-pkg-v0.3.1) - 2026-04-03

### Other

- bump pg-core to 0.5.7 with all deps in sync
- add keywords metadata to pg-pkg

## [0.3.0](https://github.com/encryption4all/postguard/releases/tag/pg-pkg-v0.3.0) - 2026-04-02

### Added

- integrate release-plz for automated releases
- update pkg documentation
- change sign keys endpoint for our needs
- add retrieving multiple signing keys by POSTing subsets

### Fixed

- replace wildcard dependency versions with concrete ranges
- move attribute filtering and session building back to start handler
- filter empty attribute values in Yivi disclosure session
- pg-cli now correctly retrieves two seperate signing keys
- make sure older versions derive the same KEM identities, add a test to detect if this doesn't happen

### Other

- Merge branch 'main' into fix/enforce-attribute-value-in-yivi-session
- Merge pull request #54 from encryption4all/fix/ring-security-vulnerability
- Fix cargo fmt: join chained method call onto single line
- Re-add unauth flow
- Make irma_token not required, as irma servers can be unauthenticated for testing/developing
- API key added to CLI tool and PKG ([#43](https://github.com/encryption4all/postguard/pull/43))
- Update start.rs
- added even more logging to be SURE what the issue is
- Perhaps actually use the errors I make
- better error handling for client not making
- added health endpoint for k8s
- fmt
- docker file and compose work
- added token auth + the run command, works with the demo now
- Remove attribute values for signing ([#32](https://github.com/encryption4all/postguard/pull/32))
- 0.3.0 rc.0 ([#20](https://github.com/encryption4all/postguard/pull/20))

### Removed

- removed log messages
