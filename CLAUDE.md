# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PostGuard is an Identity-Based Encryption (IBE) service using Yivi authentication. The system enables anyone to encrypt messages using only the recipient's identity and a master public key. Recipients prove their identity to a Private Key Generator (PKG) to obtain decryption keys.

**Security Notice**: This implementation has not been audited. Use at your own risk.

## Build Commands

### Build All Crates
```bash
cargo build --release
```

### Build Specific Crates
```bash
# Core library only
cargo build -p pg-core --release

# PKG server
cargo build -p pg-pkg --release

# CLI client
cargo build -p pg-cli --release

# WebAssembly bindings
cd pg-wasm && wasm-pack build --release -d pkg/ --out-name index --scope e4a --target bundler
```

### Testing
```bash
# Run all tests
cargo test

# Test WASM bindings (requires Chrome)
cd pg-wasm && wasm-pack test --chrome --headless

# Run benchmarks (requires test, rust, and stream features)
cargo bench
```

## Running the PKG Server

### First-time Setup
Generate IBE and IBS key pairs:
```bash
cargo run --release --bin pg-pkg gen
```

This creates default key files: `pkg_ibe.pub`, `pkg_ibe.sec`, `pkg_ibs.pub`, `pkg_ibs.sec`

### Start Server
```bash
cargo run --release --bin pg-pkg server -t <IRMA_TOKEN> -i <IRMA_SERVER_URL>
```

Default server runs on `0.0.0.0:8087`

### Using Docker
```bash
# With docker-compose (requires .env file with PG_TOKEN and IRMA_SERVER)
docker-compose up

# Build and run manually
docker build -t pg-pkg .
docker run -p 8087:8087 -e PG_TOKEN=<token> -e IRMA_SERVER=<url> pg-pkg
```

## Using the CLI Client

```bash
# Encrypt a file
cargo run --release --bin pg-cli enc <input_file> <output_file>

# Decrypt a file
cargo run --release --bin pg-cli dec <input_file> <output_file>
```

## Architecture

### Workspace Structure

PostGuard is organized as a Cargo workspace with four member crates:

- **pg-core**: Core cryptographic library (no_std)
- **pg-pkg**: HTTP API server (actix-web) running the PKG
- **pg-cli**: Command-line client for encryption/decryption
- **pg-wasm**: WebAssembly bindings for browser usage

### Cryptographic Protocol

The system implements a hybrid Sign-then-Encrypt protocol:

1. **KEM (Key Encapsulation)**: Uses Multi-Recipient Identity-Based KEM (mIBKEM) to encapsulate shared secrets for recipients based on their identities
2. **Sign**: Header and ciphertexts are signed using identity-based signatures (IBS) under the sender's identity
3. **DEM (Data Encapsulation)**: Payload encrypted with AES-GCM using the shared secret as symmetric key

### Wire Format

```
PREAMBLE (10 bytes)
  = PRELUDE (4) || VERSION (2) || HEADER LEN (4)

HEADER (variable)
  = HEADER || HEADER SIG LEN (4) || HEADER SIG (*)

PAYLOAD (variable)
  = DEM.Enc(MESSAGE || STREAM SIG || STREAM SIG LEN (4))
```

### Core Library (pg-core)

The core is a `no_std` library with two symmetric crypto backends:

- **Rust Crypto** (`rust` feature, default): Uses RustCrypto crates
- **Web Crypto** (`web` feature): Leverages browser WebCrypto API for WASM

Two operational modes:

- **In-memory** (default): Entire message encrypted/decrypted at once using AEAD
- **Streaming** (`stream` feature): Processes arbitrary-sized data in segments with per-segment authentication (based on [Online Authenticated-Encryption](https://eprint.iacr.org/2015/189.pdf))

Key modules:
- `api`: Public API definitions
- `artifacts`: Serialization of keys, ciphertexts, signatures
- `identity`: Policy and attribute management
- `client`: Sealer/Unsealer implementations split by backend (`rust`/`web`)

### PKG Server (pg-pkg)

An actix-web HTTP server implementing the PKG with these key components:

**Handlers** (`src/handlers/`):
- `parameters.rs`: Serves public keys (`GET /v2/parameters`, `/v2/sign/parameters`)
- `start.rs`: Initiates Yivi authentication sessions (`POST /v2/irma/start`)
- `jwt.rs`: Returns signed JWTs after authentication (`GET /v2/irma/jwt/{token}`)
- `key.rs`: Issues decryption keys (`GET /v2/irma/key/{timestamp}`)
- `signing_key.rs`: Issues signing keys (`POST /v2/irma/sign/key`)
- `health.rs`: Health check endpoint
- `metrics.rs`: Prometheus metrics

**Middleware** (`src/middleware/`):
- `irma.rs`: JWT validation and authentication
- `metrics.rs`: Request/response metrics collection

The server validates identity proofs via Yivi (IRMA) server integration, requiring a JWT private key configured on the IRMA server for signed session results.

### CLI Client (pg-cli)

Tokio-based async CLI with subcommands for encryption (`enc`) and decryption (`dec`). Handles:
- PKG communication for key retrieval
- Yivi session management (displays QR codes for authentication)
- File I/O with progress indicators
- Policy construction from user input

Key modules:
- `client.rs`: PKG API client
- `encrypt.rs`: Encryption workflow
- `decrypt.rs`: Decryption workflow

### WASM Bindings (pg-wasm)

Exposes PostGuard to JavaScript/TypeScript via wasm-bindgen. Optimized for browser usage with bundlers.

Exports:
- `sealStream()`: Encrypts ReadableStream to WritableStream
- `seal()`: Encrypts Uint8Array
- `StreamUnsealer`: Class for decrypting streams
- `Unsealer`: Class for decrypting Uint8Array

Requires `ReadableStream` and `WritableStream` APIs (Firefox 100+). Use [web-streams-polyfill](https://www.npmjs.com/package/web-streams-polyfill) for older browsers.

## Authentication via Yivi

PostGuard uses [Yivi (formerly IRMA)](https://yivi.app) for privacy-friendly identity verification. Users store uniquely identifying attributes in the Yivi mobile app and selectively disclose them with explicit consent.

The PKG validates these disclosed attributes against encryption policies before issuing decryption keys.

## Key Dependencies

- **ibe**: Identity-Based Encryption primitives (CGWKV scheme with multi-recipient support)
- **ibs**: Identity-Based Signature scheme
- **actix-web**: Web framework for PKG server
- **wasm-pack**: WebAssembly compilation toolchain
- **irma**: Yivi/IRMA protocol client library

## Development Notes

- The workspace uses resolver="2" for dependency resolution
- Release builds enable LTO (Link-Time Optimization) for all crates
- WASM builds use opt-level="s" for size optimization
- pg-core denies unsafe code and enforces documentation
