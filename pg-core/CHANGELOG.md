# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.4](https://github.com/encryption4all/postguard/compare/pg-core-v0.6.3...pg-core-v0.6.4) - 2026-08-18

### Added

- *(pg-core)* canonicalize identity attribute values before deriving ([#335](https://github.com/encryption4all/postguard/pull/335))

### Fixed

- *(pg-core)* bind the public signing policy into the AEAD plaintext ([#351](https://github.com/encryption4all/postguard/pull/351))
- *(pg-core)* name the version constants after their wire values ([#345](https://github.com/encryption4all/postguard/pull/345))

### Other

- assert main's ruleset still requires the gate build.yml produces ([#333](https://github.com/encryption4all/postguard/pull/333))

## [0.6.3](https://github.com/encryption4all/postguard/compare/pg-core-v0.6.2...pg-core-v0.6.3) - 2026-08-10

### Other

- *(pg-core)* assert build.yml's gate wiring so an unapplied patch fails loudly ([#316](https://github.com/encryption4all/postguard/pull/316))

## [0.6.2](https://github.com/encryption4all/postguard/compare/pg-core-v0.6.1...pg-core-v0.6.2) - 2026-07-30

### Added

- *(api)* pin the v2 HTTP contract and reject unknown request fields ([#242](https://github.com/encryption4all/postguard/pull/242))
- *(api)* accept Yivi condiscon in IrmaAuthRequest ([#198](https://github.com/encryption4all/postguard/pull/198))

### Fixed

- bound stream signature length ([#228](https://github.com/encryption4all/postguard/pull/228))

### Other

- *(compat)* HEAD sample sealer plus published pg-core reader crate ([#265](https://github.com/encryption4all/postguard/pull/265))
- *(core)* golden wire-format fixtures pin VERSION_V3 in-repo ([#243](https://github.com/encryption4all/postguard/pull/243))
- clear clippy warning backlog for the clippy CI job ([#193](https://github.com/encryption4all/postguard/pull/193)) ([#229](https://github.com/encryption4all/postguard/pull/229))
- consume irmars from crates.io and bump reqwest to 0.12 ([#192](https://github.com/encryption4all/postguard/pull/192))
- bump bincode-next 3.0.0-rc.13 to 3.0.0-rc.14 ([#191](https://github.com/encryption4all/postguard/pull/191))

## [0.6.1](https://github.com/encryption4all/postguard/compare/pg-core-v0.6.0...pg-core-v0.6.1) - 2026-05-16

### Other

- refresh deps and bump criterion / indicatif / qrcode / twox-hash

## [0.5.10](https://github.com/encryption4all/postguard/compare/pg-core-v0.5.9...pg-core-v0.5.10) - 2026-04-24

### Fixed

- correct typos and outdated references in READMEs

### Other

- fix two spelling typos in crate-level doc comments

## [0.5.9](https://github.com/encryption4all/postguard/compare/pg-core-v0.5.8...pg-core-v0.5.9) - 2026-04-10

### Added

- support optional attributes in Yivi disclosure sessions

## [0.5.8](https://github.com/encryption4all/postguard/compare/pg-core-v0.5.7...pg-core-v0.5.8) - 2026-04-03

### Other

- add categories to pg-pkg, improve pg-core description

## [0.3.1](https://github.com/encryption4all/postguard/compare/pg-core-v0.3.0...pg-core-v0.3.1) - 2026-04-02

### Other

- update Cargo.toml dependencies
