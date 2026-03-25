---
sidebar_position: 1
slug: /intro
---

# Introduction

PostGuard is an **Identity-Based Encryption (IBE)** system that enables privacy-friendly encryption using [Yivi](https://yivi.app/) identity attributes. Senders encrypt messages to recipients using only their public identity (e.g., an email address), and recipients prove ownership of those attributes via Yivi to obtain decryption keys.

## How It Works

1. A **Private Key Generator (PKG)** holds a master key pair.
2. A sender encrypts a message for a recipient using the PKG's **master public key** and the recipient's **identity attributes** (e.g., email address).
3. The recipient proves they own the required attributes via a **Yivi disclosure session**.
4. The PKG issues a **User Secret Key (USK)** that allows the recipient to decrypt.

No prior key exchange is needed — the sender only needs to know the recipient's identity.

## Components

PostGuard is a Rust workspace consisting of four crates:

| Crate | Description |
|-------|-------------|
| **pg-core** | Core cryptographic library implementing the Sign-then-Encrypt (StE) hybrid protocol |
| **pg-pkg** | HTTP API server — the Private Key Generator that validates identities via Yivi and issues keys |
| **pg-cli** | Command-line client for encrypting and decrypting files |
| **pg-wasm** | WebAssembly bindings for browser-based encryption (published as `@e4a/pg-wasm` on npm) |

## Cryptographic Primitives

- **KEM**: CGW-KV anonymous IBE scheme on BLS12-381 (from the [`ibe`](https://crates.io/crates/ibe) crate)
- **IBS**: GG identity-based signatures (from the [`ibs`](https://crates.io/crates/ibs) crate)
- **Symmetric**: AES-128-GCM (128-bit security to match BLS12-381)
- **Hashing**: SHA3-512 for identity derivation

## License

PostGuard is licensed under the [MIT License](https://github.com/encryption4all/postguard/blob/main/LICENSE).

:::warning
This is unaudited software. Use at your own risk.
:::
