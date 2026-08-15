# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.8](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.7...pg-cli-v0.3.8) - 2026-08-10

### Other

- update Cargo.lock dependencies

## [0.3.7](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.6...pg-cli-v0.3.7) - 2026-07-30

### Added

- *(api)* accept Yivi condiscon in IrmaAuthRequest ([#198](https://github.com/encryption4all/postguard/pull/198))

### Other

- *(pg-cli)* drop useless borrow in decrypt eprintln (clippy) ([#231](https://github.com/encryption4all/postguard/pull/231))
- bump reqwest 0.12 → 0.13 and inquire 0.6 → 0.9 ([#196](https://github.com/encryption4all/postguard/pull/196))
- consume irmars from crates.io and bump reqwest to 0.12 ([#192](https://github.com/encryption4all/postguard/pull/192))

## [0.3.6](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.5...pg-cli-v0.3.6) - 2026-05-16

### Other

- refresh deps and bump criterion / indicatif / qrcode / twox-hash
- migrate from bincode 1.3.3 to bincode-next 3.0.0-rc.13
- Merge branch 'main' into fix/pg-cli-unwrap-156
- replace lazy_static with std::sync::LazyLock

## [0.3.5](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.4...pg-cli-v0.3.5) - 2026-04-24

### Other

- update Cargo.lock dependencies

## [0.3.4](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.3...pg-cli-v0.3.4) - 2026-04-10

### Added

- support optional attributes in Yivi disclosure sessions

## [0.3.3](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.2...pg-cli-v0.3.3) - 2026-04-03

### Other

- add categories metadata to pg-cli

## [0.3.2](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.1...pg-cli-v0.3.2) - 2026-04-03

### Added

- sync pg-core and pg-wasm versions, exclude pg-wasm from workspace

### Other

- bump pg-core to 0.5.7 with all deps in sync
- add repository metadata to pg-cli
- add keywords metadata to pg-cli
- add homepage/repository metadata to all crates

## [0.3.1](https://github.com/encryption4all/postguard/compare/pg-cli-v0.3.0...pg-cli-v0.3.1) - 2026-04-02

### Other

- updated the following local packages: pg-core
