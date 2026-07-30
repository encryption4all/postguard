# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- require a validated API key on `GET /usage` and reject unauthenticated callers with 401 (GHSA-5rhx-xgvv-h78h)
- compare `cryptify_token` values in constant time, matching the recovery-token path

## [0.1.27](https://github.com/encryption4all/cryptify/compare/v0.1.26...v0.1.27) - 2026-05-16

### Added

- staging_mode config that logs instead of sending email
- *(upload)* GET /fileupload/{uuid}/status for cross-refresh resume

### Fixed

- address dead UUID check and copy-paste error in upload_chunk
- add HTTP Range support to /filedownload

### Other

- add regression test for invalid_uuid reason on upload_chunk
- resolve conflicts with main (download route)
- *(upload)* cover /status preflight + deadline-extension AC

## [0.1.26](https://github.com/encryption4all/cryptify/compare/v0.1.25...v0.1.26) - 2026-05-07

### Added

- *(upload)* idempotent retry of the last committed chunk
- *(upload)* structured 404 body, configurable session TTL

### Fixed

- validate API key against pg-pkg, not a local allowlist (closes #123)

### Other

- *(upload)* apply review feedback from #145
- Merge pull request #132 from encryption4all/fix/extend-upload-eviction-on-chunk
- Merge pull request #141 from encryption4all/dependabot/cargo/openssl-0.10.79
- Merge remote-tracking branch 'origin/main' into fix/upload-init-orphan-files-125
- update dependencies
- add Rust quality job (fmt, clippy, test)

## [0.1.25](https://github.com/encryption4all/cryptify/compare/v0.1.24...v0.1.25) - 2026-05-02

### Added

- *(upload)* add notifyRecipients toggle on /fileupload/init

### Other

- Merge pull request #135 from encryption4all/feat/notify-recipients-toggle

## [0.1.24](https://github.com/encryption4all/cryptify/compare/v0.1.23...v0.1.24) - 2026-04-30

### Other

- Merge pull request #113 from encryption4all/dependabot/cargo/rustls-webpki-0.103.13
- Merge pull request #128 from encryption4all/dependabot/cargo/openssl-0.10.78
- Merge remote-tracking branch 'origin/main' into chore/strum-0.28
- Merge remote-tracking branch 'origin/main' into dobby/reqwest-0.13
- Merge pull request #121 from encryption4all/dobby/sha2-rand
- Merge pull request #122 from encryption4all/dobby/pg-core-0.5
- *(deps)* bump pg-core to 0.5

## [0.1.23](https://github.com/encryption4all/cryptify/compare/v0.1.22...v0.1.23) - 2026-04-26

### Other

- *(api)* align upload limit descriptions with current constants

## [0.1.22](https://github.com/encryption4all/cryptify/compare/v0.1.21...v0.1.22) - 2026-04-24

### Added

- make chunk size configurable via TOML, default 5 MB
- tiered upload limits for API key users, 10 MiB chunks, resets_at in 413
- enforce server-side upload limits (5 GiB/upload, 15 GiB rolling/email)

### Fixed

- align upload limits to round GB values (5 GB / 100 GB)
- use GB instead of GiB in API description
- *(upload)* raise Rocket data limits to match CHUNK_SIZE

### Other

- Merge branch 'main' into feat/x-postguard-email-header
- Merge pull request #105 from encryption4all/fix/upload-chunk-data-limit
- remove outdated cryptify-frontend/backend references
- Add PostGuard logo to README
- Standardize README

## [0.1.21](https://github.com/encryption4all/cryptify/compare/v0.1.20...v0.1.21) - 2026-04-20

### Other

- cargo update to refresh dependencies and resolve advisories
- Fix release-plz creating PRs when nothing changed

## [0.1.20](https://github.com/encryption4all/cryptify/compare/v0.1.19...v0.1.20) - 2026-04-03

### Other

- Use high-res PostGuard logo with text in email template

## [0.1.19](https://github.com/encryption4all/cryptify/compare/v0.1.18...v0.1.19) - 2026-03-30

### Other

- Merge branch 'main' into add-explanation
- Update build pipeline versions

## [0.1.18](https://github.com/encryption4all/cryptify/compare/v0.1.17...v0.1.18) - 2026-03-30

### Other

- Use native runners
- Try 24375738 to make the pipeline work

## [0.1.17](https://github.com/encryption4all/cryptify/compare/v0.1.16...v0.1.17) - 2026-03-27

### Other

- Upload to ghcr instead of docker
- Switch to docker specified workflow
- Move anchore scan
- Disable arm/amd build publish
- Try 100 version of automated release

## [0.1.16](https://github.com/encryption4all/cryptify/compare/v0.1.15...v0.1.16) - 2026-03-27

### Other

- Disable main build on push

## [0.1.15](https://github.com/encryption4all/cryptify/compare/v0.1.14...v0.1.15) - 2026-03-27

### Other

- try the rlsplz way

## [0.1.14](https://github.com/encryption4all/cryptify/compare/v0.1.13...v0.1.14) - 2026-03-27

### Other

- use one workflow file

## [0.1.13](https://github.com/encryption4all/cryptify/compare/v0.1.12...v0.1.13) - 2026-03-27

### Other

- Run on tag push

## [0.1.12](https://github.com/encryption4all/cryptify/compare/v0.1.11...v0.1.12) - 2026-03-27

### Other

- Run on release-plz completion

## [0.1.11](https://github.com/encryption4all/cryptify/compare/v0.1.10...v0.1.11) - 2026-03-27

### Other

- Try other tag based flow

## [0.1.10](https://github.com/encryption4all/cryptify/compare/v0.1.9...v0.1.10) - 2026-03-27

### Other

- Add rlsplz dependency

## [0.1.9](https://github.com/encryption4all/cryptify/compare/v0.1.8...v0.1.9) - 2026-03-27

### Added

- one qr code for signature
- add button to include sender confirmation
- add sent confirmation, also encrypt for sender
- keep the border around the file box
- apply more of Jorrits new design
- add filesharing to multiple recipients
- more work on signatures
- update pg-wasm package
- change postguard pkg url
- add sender verification and update rocket to rc3
- include metrics header in all PKG requests
- retrieve lang setting via message
- add example irma server configuration
- determine backend url automatically
- bump wasm dependency to 0.2.2
- add swapped font
- minor style changes to match embedded design
- remove rocket cors for now, since backend and frontend are on the same host
- update docker-compose config
- feat add/update docker-compose configurations
- only expose nginx service from host
- frontend and backend on same origin

### Fixed

- semver version on release
- scope config.toml gitignore pattern to repo root only
- add initial v0.1.0 changelog entry to prevent release-plz from including all history
- trigger delivery on tag push so semver Docker tags are applied
- remove invalid command value from release-plz workflow
- replace checkmark SVG with HTML/unicode equivalent in email ([#29](https://github.com/encryption4all/cryptify/pull/29))
- replace SVG with PNG in email template ([#29](https://github.com/encryption4all/cryptify/pull/29))
- keep one recipient, clear when removed
- scrollable column
- use correct language in EncryptPanel
- translation and layout fixes
- start command in dev setup
- remove/rename irma/mailhog correctly
- wrong expiry date calculation
- height input file button in dutch
- minor changes to message textarea css
- actually use irma token in onEncrypt()
- sending e-mails now work in debug and release mode
- several front-end bugfixes
- typos
- backend config read correctly
- trailing slash backend url
- set public path correctly
- production-like config.toml
- error in dev config
- fix some post-merge errors
- fix conflicts
- force lowercase email address
- dont use form in DecryptPanel, since button in form uses has

### Other

- release v0.1.8
- Disable release-plz cargo publishing
- Add id-token write
- release v0.1.7
- Reset release-plz to defaults
- release v0.1.6
- release v0.1.5
- move Rust crate from cryptify/ subdirectory to repo root
- release v0.1.4
- Merge pull request #68 from encryption4all/fix/release-plz-setup
- release v0.1.1
- add package description to Cargo.toml
- update Rust edition from 2018 to 2021
- add repository and license metadata to Cargo.toml
- Merge pull request #58 from encryption4all/feat/release-plz
- Update pipeline action versions
- Add release-plz
- *(deps)* bump rustls-webpki from 0.103.8 to 0.103.10 in /cryptify
- Merge pull request #50 from encryption4all/dependabot/cargo/cryptify/time-0.3.47
- Merge pull request #49 from encryption4all/dependabot/cargo/cryptify/bytes-1.11.1
- *(deps)* bump bytes from 1.10.1 to 1.11.1 in /cryptify
- upgrade anchore/scan-action to v7.3.2 and codeql-action to v4
- Move imdage name from  cryptify-backend to cryptify
- Split Docker build into native amd64/arm64 jobs, add cargo-chef caching
- Add poll watching for claude code
- Change email template to match design
- Merge pull request #46 from encryption4all/rm-frontend
- Change url send confirmation
- Add SMTP logging and connection timeout to email sending
- Add 10s timeout to PKG fetch to prevent silent startup hang
- Change error to properly print url
- Add better error msg for pkg fetch
- Fix CI deployment
- Change email url
- Rename cryptify-backend to cryptify
- Add dockerignore to cut build context
- Change pkg_url in dev.toml
- Improve dev setup and update API description
- Remove frontend
- Remove frontend and clean up unused deployment files
- Add docker-compose.dev.yml for local development
- Update dev configuration for Rocket compatibility
- Add development Dockerfile for frontend
- Add development Dockerfile for backend with cargo-chef
- Remove double wasm types definition nginx.conf
- Use matrix builds for faster build times
- Use hashes instead of tags to prevent potential sidechain attacks
- External config file ([#31](https://github.com/encryption4all/cryptify/pull/31))
- Frontend docker file ([#30](https://github.com/encryption4all/cryptify/pull/30))
- Frontend docker file ([#29](https://github.com/encryption4all/cryptify/pull/29))
- Made a docker file for the frontend ([#28](https://github.com/encryption4all/cryptify/pull/28))
- I do not know how it got built with docker, now builds with command line too
- Added health endpoint ([#27](https://github.com/encryption4all/cryptify/pull/27))
- expose port
- Updated deps and made workflow for delivery ([#26](https://github.com/encryption4all/cryptify/pull/26))
- Update PKG URL
- Updated env var
- Update env variable
- Updated env vars
- Updated backend url to use main env
- Merge branch 'main' of https://github.com/encryption4all/cryptify
- Updated PKG URL
- Merge branch 'main' of https://github.com/encryption4all/cryptify
- Updated pg-wasm version
- Merge branch 'stable' into main
- *(deps)* update pg-wasm 0.3.0
- remove yivi css
- more work on layout
- change to sign and send button
- small changes
- merge main
- small changes
- use new pkg urls
- initial signature support
- remove unused encrypt panel code
- update to released version of lettre, minor other changes
- use PUBLIC_URL env variable
- small changes
- embed version of cryptify
- postguard embed version
- Merge branch 'dev'
- update readme
- add backend dockerfile
- update package-lock.json
- update docker-compose config
- update gitignore
- simplify decryptPanel
- small changes to compose
- remove old deployment files
- for now, don't include cors settings
- move dev config file to conf/
- remove unused old CORS config
- remove unused responders structs
- changes to verification code and setup CORS configuration
- simplify encryption process
- Merge main including sender authentication in dev branch
- Merge branch 'main' into add-email-verification
- Merge pull request #1 from arjentz/add-rust-backend
- Processed review
- Fix docker-compose.dev.yml
- Add development setup
- Remove metadata, cargo clippy, cargo fmt
- Update backend to match frontend changes
- Uncomment some proper checks
- Add code from rust backend
- Final sync to github
- Initial commit.
- Update README.md
- Update README.md
- Delete LICENSE
- Create LICENSE
- Initial commit

## [0.1.8](https://github.com/encryption4all/cryptify/compare/v0.1.7...v0.1.8) - 2026-03-27

### Fixed

- semver version on release

## [0.1.7](https://github.com/encryption4all/cryptify/compare/v0.1.6...v0.1.7) - 2026-03-27

### Other

- Reset release-plz to defaults

## [0.1.6](https://github.com/encryption4all/cryptify/compare/v0.1.5...v0.1.6) - 2026-03-27

### Added

- one qr code for signature
- add button to include sender confirmation
- add sent confirmation, also encrypt for sender
- keep the border around the file box
- apply more of Jorrits new design
- add filesharing to multiple recipients
- more work on signatures
- update pg-wasm package
- change postguard pkg url
- add sender verification and update rocket to rc3
- include metrics header in all PKG requests
- retrieve lang setting via message
- add example irma server configuration
- determine backend url automatically
- bump wasm dependency to 0.2.2
- add swapped font
- minor style changes to match embedded design
- remove rocket cors for now, since backend and frontend are on the same host
- update docker-compose config
- feat add/update docker-compose configurations
- only expose nginx service from host
- frontend and backend on same origin

### Fixed

- scope config.toml gitignore pattern to repo root only
- add initial v0.1.0 changelog entry to prevent release-plz from including all history
- trigger delivery on tag push so semver Docker tags are applied
- remove invalid command value from release-plz workflow
- replace checkmark SVG with HTML/unicode equivalent in email ([#29](https://github.com/encryption4all/cryptify/pull/29))
- replace SVG with PNG in email template ([#29](https://github.com/encryption4all/cryptify/pull/29))
- keep one recipient, clear when removed
- scrollable column
- use correct language in EncryptPanel
- translation and layout fixes
- start command in dev setup
- remove/rename irma/mailhog correctly
- wrong expiry date calculation
- height input file button in dutch
- minor changes to message textarea css
- actually use irma token in onEncrypt()
- sending e-mails now work in debug and release mode
- several front-end bugfixes
- typos
- backend config read correctly
- trailing slash backend url
- set public path correctly
- production-like config.toml
- error in dev config
- fix some post-merge errors
- fix conflicts
- force lowercase email address
- dont use form in DecryptPanel, since button in form uses has

### Other

- release v0.1.5
- move Rust crate from cryptify/ subdirectory to repo root
- release v0.1.4
- Merge pull request #68 from encryption4all/fix/release-plz-setup
- release v0.1.1
- add package description to Cargo.toml
- update Rust edition from 2018 to 2021
- add repository and license metadata to Cargo.toml
- Merge pull request #58 from encryption4all/feat/release-plz
- Update pipeline action versions
- Add release-plz
- *(deps)* bump rustls-webpki from 0.103.8 to 0.103.10 in /cryptify
- Merge pull request #50 from encryption4all/dependabot/cargo/cryptify/time-0.3.47
- Merge pull request #49 from encryption4all/dependabot/cargo/cryptify/bytes-1.11.1
- *(deps)* bump bytes from 1.10.1 to 1.11.1 in /cryptify
- upgrade anchore/scan-action to v7.3.2 and codeql-action to v4
- Move imdage name from  cryptify-backend to cryptify
- Split Docker build into native amd64/arm64 jobs, add cargo-chef caching
- Add poll watching for claude code
- Change email template to match design
- Merge pull request #46 from encryption4all/rm-frontend
- Change url send confirmation
- Add SMTP logging and connection timeout to email sending
- Add 10s timeout to PKG fetch to prevent silent startup hang
- Change error to properly print url
- Add better error msg for pkg fetch
- Fix CI deployment
- Change email url
- Rename cryptify-backend to cryptify
- Add dockerignore to cut build context
- Change pkg_url in dev.toml
- Improve dev setup and update API description
- Remove frontend
- Remove frontend and clean up unused deployment files
- Add docker-compose.dev.yml for local development
- Update dev configuration for Rocket compatibility
- Add development Dockerfile for frontend
- Add development Dockerfile for backend with cargo-chef
- Remove double wasm types definition nginx.conf
- Use matrix builds for faster build times
- Use hashes instead of tags to prevent potential sidechain attacks
- External config file ([#31](https://github.com/encryption4all/cryptify/pull/31))
- Frontend docker file ([#30](https://github.com/encryption4all/cryptify/pull/30))
- Frontend docker file ([#29](https://github.com/encryption4all/cryptify/pull/29))
- Made a docker file for the frontend ([#28](https://github.com/encryption4all/cryptify/pull/28))
- I do not know how it got built with docker, now builds with command line too
- Added health endpoint ([#27](https://github.com/encryption4all/cryptify/pull/27))
- expose port
- Updated deps and made workflow for delivery ([#26](https://github.com/encryption4all/cryptify/pull/26))
- Update PKG URL
- Updated env var
- Update env variable
- Updated env vars
- Updated backend url to use main env
- Merge branch 'main' of https://github.com/encryption4all/cryptify
- Updated PKG URL
- Merge branch 'main' of https://github.com/encryption4all/cryptify
- Updated pg-wasm version
- Merge branch 'stable' into main
- *(deps)* update pg-wasm 0.3.0
- remove yivi css
- more work on layout
- change to sign and send button
- small changes
- merge main
- small changes
- use new pkg urls
- initial signature support
- remove unused encrypt panel code
- update to released version of lettre, minor other changes
- use PUBLIC_URL env variable
- small changes
- embed version of cryptify
- postguard embed version
- Merge branch 'dev'
- update readme
- add backend dockerfile
- update package-lock.json
- update docker-compose config
- update gitignore
- simplify decryptPanel
- small changes to compose
- remove old deployment files
- for now, don't include cors settings
- move dev config file to conf/
- remove unused old CORS config
- remove unused responders structs
- changes to verification code and setup CORS configuration
- simplify encryption process
- Merge main including sender authentication in dev branch
- Merge branch 'main' into add-email-verification
- Merge pull request #1 from arjentz/add-rust-backend
- Processed review
- Fix docker-compose.dev.yml
- Add development setup
- Remove metadata, cargo clippy, cargo fmt
- Update backend to match frontend changes
- Uncomment some proper checks
- Add code from rust backend
- Final sync to github
- Initial commit.
- Update README.md
- Update README.md
- Delete LICENSE
- Create LICENSE
- Initial commit

## [0.1.5](https://github.com/encryption4all/cryptify/compare/v0.1.4...v0.1.5) - 2026-03-27

### Fixed

- add initial v0.1.0 changelog entry to prevent release-plz from including all history
- replace checkmark SVG with HTML/unicode equivalent in email ([#29](https://github.com/encryption4all/cryptify/pull/29))
- replace SVG with PNG in email template ([#29](https://github.com/encryption4all/cryptify/pull/29))

### Other

- release v0.1.4
- Merge pull request #68 from encryption4all/fix/release-plz-setup
- release v0.1.1
- add package description to Cargo.toml
- update Rust edition from 2018 to 2021
- add repository and license metadata to Cargo.toml
- Split smtp credentials into username password
- *(deps)* bump rustls-webpki from 0.103.8 to 0.103.10 in /cryptify
- Merge pull request #50 from encryption4all/dependabot/cargo/cryptify/time-0.3.47
- Merge pull request #49 from encryption4all/dependabot/cargo/cryptify/bytes-1.11.1
- *(deps)* bump bytes from 1.10.1 to 1.11.1 in /cryptify
- Split Docker build into native amd64/arm64 jobs, add cargo-chef caching
- Change email template to match design
- Change url send confirmation
- Add SMTP logging and connection timeout to email sending
- Add 10s timeout to PKG fetch to prevent silent startup hang
- Change error to properly print url
- Add better error msg for pkg fetch
- Change email url
- Rename cryptify-backend to cryptify

## [0.1.4](https://github.com/encryption4all/cryptify/compare/v0.1.3...v0.1.4) - 2026-03-27

### Fixed

- add initial v0.1.0 changelog entry to prevent release-plz from including all history

### Other

- Merge pull request #68 from encryption4all/fix/release-plz-setup

## [0.1.3](https://github.com/encryption4all/cryptify/compare/v0.1.2...v0.1.3) - 2026-03-26

### Fixed

- replace checkmark SVG with HTML/unicode equivalent in email ([#29](https://github.com/encryption4all/cryptify/pull/29))
- replace SVG with PNG in email template ([#29](https://github.com/encryption4all/cryptify/pull/29))

### Other

- release v0.1.2
- release v0.1.1
- add package description to Cargo.toml
- update Rust edition from 2018 to 2021
- add repository and license metadata to Cargo.toml
- Split smtp credentials into username password
- *(deps)* bump rustls-webpki from 0.103.8 to 0.103.10 in /cryptify
- Merge pull request #50 from encryption4all/dependabot/cargo/cryptify/time-0.3.47
- Merge pull request #49 from encryption4all/dependabot/cargo/cryptify/bytes-1.11.1
- *(deps)* bump bytes from 1.10.1 to 1.11.1 in /cryptify
- Split Docker build into native amd64/arm64 jobs, add cargo-chef caching
- Change email template to match design
- Change url send confirmation
- Add SMTP logging and connection timeout to email sending
- Add 10s timeout to PKG fetch to prevent silent startup hang
- Change error to properly print url
- Add better error msg for pkg fetch
- Change email url
- Rename cryptify-backend to cryptify

## [0.1.2](https://github.com/encryption4all/cryptify/compare/v0.1.1...v0.1.2) - 2026-03-26

### Other

- update Cargo.toml dependencies

## [0.1.1](https://github.com/encryption4all/cryptify/compare/v0.1.0...v0.1.1) - 2026-03-26

### Other

- add package description to Cargo.toml
- update Rust edition from 2018 to 2021

## [0.1.0] - 2026-03-26

Initial release.
