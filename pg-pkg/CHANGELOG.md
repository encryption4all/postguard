# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
