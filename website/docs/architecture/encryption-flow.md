---
sidebar_position: 2
---

# Encryption & Decryption Flow

This page describes the detailed cryptographic flow for encrypting and decrypting messages in PostGuard.

## Encryption (Sealing)

### 1. Fetch Public Parameters

The sender retrieves the master public key (MPK) and verification key (VK) from the PKG:

```
GET /v2/parameters       -> PublicKey (IBE master public key)
GET /v2/sign/parameters  -> VerifyingKey (IBS verification key)
```

### 2. Obtain Signing Keys

The sender requests signing keys from the PKG. This requires a Yivi disclosure session or an API key:

```
POST /v2/irma/start         -> Start Yivi session
GET  /v2/irma/jwt/{token}   -> Retrieve JWT after disclosure
POST /v2/irma/sign/key      -> Get SigningKeyExt (public + optional private)
```

### 3. Build Header

For each recipient, the sender defines a `Policy` containing:
- A **timestamp** (for key rotation / temporal binding)
- A **conjunction of attributes** (e.g., `pbdf.sidn-pbdf.email.email = alice@example.com`)

The policy is hashed into a 64-byte **KEM identity** using SHA3-512:

```
identity = SHA3-512(0 || f_0 || f'_0 || ... || f_{n-1} || f'_{n-1} || timestamp)

where:
  f_i  = SHA3-512(2i+1 || type_len || type_bytes)
  f'_i = SHA3-512(2i+2 || value_len || value_bytes)  // or SHA3-512(u64::MAX) if no value
```

A single **multi-recipient KEM encapsulation** produces a shared secret and per-recipient ciphertexts.

### 4. Encrypt Payload

The shared secret is used to derive an AES-128-GCM key. The plaintext is encrypted along with an IBS signature from the sender.

**In-memory mode**: The entire plaintext is encrypted as a single AES-128-GCM ciphertext.

**Streaming mode**: The plaintext is split into 256 KiB segments, each encrypted and authenticated separately using the STREAM construction.

### 5. Output

The ciphertext is assembled as: `PREAMBLE || HEADER || HEADER_SIG || ENCRYPTED_PAYLOAD`

## Decryption (Unsealing)

### 1. Parse Header

The recipient reads the preamble, version, and header from the ciphertext. The header signature is verified against the PKG's verification key.

### 2. Inspect Recipients

The header contains a `HiddenPolicy` for each recipient — this shows attribute **types** but redacts **values** (except for "hint" types that show partial values). The recipient identifies which entry corresponds to them.

### 3. Obtain User Secret Key

The recipient starts a Yivi disclosure session with the PKG, proving ownership of the required attributes:

```
POST /v2/irma/start            -> Start Yivi session with attribute constraints
GET  /v2/irma/jwt/{token}      -> Retrieve JWT after successful disclosure
GET  /v2/irma/key/{timestamp}  -> Receive User Secret Key (USK)
```

The PKG derives the same KEM identity from the disclosed attributes and timestamp, then uses the master secret key to generate the USK.

### 4. Decrypt Payload

Using the USK, the recipient:
1. **Decapsulates** the shared secret from the multi-recipient KEM ciphertext.
2. **Derives** the AES-128-GCM key.
3. **Decrypts** the payload and verifies authentication tags.
4. **Verifies** the sender's IBS signature against the verification key.

The result is the original plaintext along with a `VerificationResult` containing the sender's verified public (and optional private) signing policy.

## Multi-Recipient Support

PostGuard supports encrypting a single message for multiple recipients efficiently. The KEM encapsulation is performed once, producing a shared secret and a `MultiRecipientCiphertext` that contains per-recipient components. The payload is encrypted only once with the shared key — only the header grows with the number of recipients.
