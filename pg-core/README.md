# PostGuard Core

<p align="center">
<img
 alt=""
 width="400px"
 src="https://postguard.eu/pg_logo.svg"/>
</p>

PostGuard is cryptographic protocol that utilizes identity-based primitivesto
provide confidentiality, integrity and authenticity over messages.

⚠️ **Warning**: This implementation has not been audited and is not ready for use in production. Use at your own risk!

## Overview

This library implements a hybrid Sign-then-Encrypt (StE) protocol:

- KEM: First, a shared secret is encapsulated for all recipients using a Multi-Recipient Identity-Based Key Encapsulation (mIBKEM). The identity of the recipients is used in the encryption.

- Sign: The KEM ciphertext(s) and all information that is required for decryption is available in the
  header. The header is publicly visible and therefore all sensitive
  content is purged. The header, ciphertexts and arbitrary-long message is signed using an
  identity-based signature under the identity of the sender. This identity is only visible to
  the receivers from the previous step.

- DEM: The arbitrary-sized payload stream is written either at once (in memory) using an AEAD
  or in user-defined segments (streaming) and encrypted using the shared secret as symmetric key
  as described in the paper [Online Authenticated-Encryption and its Nonce-Reuse
  Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf).

## Symmetric Crypto Backends

This library offers two symmetric cryptography providers, [`Rust Crypto`](https://github.com/RustCrypto) and [`Web Crypto`](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The Rust Crypto
backend is by default enabled using the `rust` feature. The Web Crypto backend can be enabled
by the `web` feature, but only when targeting `wasm32-unknown-unknown`.

## Streaming vs In-memory

For large or arbitrary sized data streams, enable the `stream` feature. In this mode, during
decryption, each segment of the payload is seperately authenticated, this makes the data safe
for downstream consumers before the stream has been exhausted. Note that it is up to the
developer to choose which is suitable for their application. Only use the in-memory variant if
you are absolutely sure that you are _exclusively_ encrypting small messages.
