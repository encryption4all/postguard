# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
