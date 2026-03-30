---
sidebar_position: 2
---

# Getting Started

This guide covers how to build and run PostGuard locally for development.

## Prerequisites

- **Rust** 1.90.0 or later — install via [rustup](https://rustup.rs/)
- **Docker & Docker Compose** — for the development environment (PostgreSQL + IRMA server)
- **wasm-pack** — only needed for building the WASM bindings

```bash
# Install Rust
curl https://sh.rustup.rs -sSf | sh

# Install wasm-pack (for WASM development only)
cargo install --git https://github.com/rustwasm/wasm-pack.git
```

## Building

### Core Library

```bash
cargo build --release -p pg-core
```

### CLI Tool

```bash
cargo build --release --bin pg-cli
```

### PKG Server

```bash
# Generate master key pair
cargo run --release --bin pg-pkg gen

# Start the server
cargo run --release --bin pg-pkg server \
  -t <irma_token> \
  -i <irma_server_url> \
  -d <postgres_url>
```

### WASM Bindings

```bash
cd pg-wasm
wasm-pack build --release -d pkg/ --out-name index --scope e4a --target bundler
```

## Development Environment

The easiest way to get a full local setup running is via Docker Compose, which starts PostgreSQL and a Yivi (IRMA) server:

```bash
docker-compose up
```

Then run the PKG server against the local services:

```bash
cargo run --release --bin pg-pkg server \
  -d postgres://devuser:devpassword@localhost/devdb \
  -t <irma_token> \
  -i http://localhost:8088
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IRMA_SERVER` | Yivi/IRMA server URL | `https://is.yivi.app` |
| `DATABASE_URL` | PostgreSQL connection string | — |
| `RUST_LOG` | Log level (`debug`, `info`, `warn`, `error`) | — |

## Using the CLI

### Encrypt a file

```bash
cargo run --bin pg-cli enc \
  -i '{"recipient@example.com": [{"t": "pbdf.sidn-pbdf.email.email", "v": "recipient@example.com"}]}' \
  --pub-sign-id '[{"t": "pbdf.gemeente.personalData.fullname"}]' \
  myfile.txt
```

This starts a Yivi session (displays a QR code) to obtain your signing keys, then encrypts `myfile.txt` into `myfile.txt.enc`.

### Decrypt a file

```bash
cargo run --bin pg-cli dec myfile.txt.enc
```

The CLI will show the recipient policies in the header, prompt you to select your identity, and start a Yivi session to obtain your decryption key.
