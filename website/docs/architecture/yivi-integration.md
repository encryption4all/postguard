---
sidebar_position: 3
---

# Yivi Integration

PostGuard uses the [Yivi](https://yivi.app/) (formerly IRMA) ecosystem for attribute-based identity verification. This page explains how Yivi sessions are used for both encryption and decryption.

## What is Yivi?

Yivi is a privacy-friendly identity platform where users store verified attributes (e.g., email address, name, BSN) in a mobile app. When a service needs to verify a user's identity, it requests a **disclosure session** — the user scans a QR code and selectively discloses only the required attributes.

## Attribute Model

In PostGuard, identities are expressed as **conjunctions of Yivi attributes**:

```json
[
  {"t": "pbdf.sidn-pbdf.email.email", "v": "alice@example.com"},
  {"t": "pbdf.gemeente.personalData.fullname", "v": "Alice Example"}
]
```

Each attribute has:
- **`t`** (type): A fully-qualified Yivi attribute identifier
- **`v`** (value): The expected attribute value (optional — omitting the value checks only that the attribute exists)

## Session Flow

### For Senders (Signing Keys)

When a sender wants to encrypt a message, they need signing keys from the PKG. The flow is:

1. **Client** calls `POST /v2/irma/start` with the sender's signing policy (which attributes identify the sender).
2. **PKG** creates an IRMA disclosure request and starts a session with the IRMA server.
3. **Sender** scans the QR code with the Yivi app and discloses the requested attributes.
4. **Client** polls or retrieves the session JWT via `GET /v2/irma/jwt/{token}`.
5. **Client** requests signing keys via `POST /v2/irma/sign/key` with the JWT as a Bearer token.
6. **PKG** validates the JWT, extracts disclosed attributes, and issues a `SigningKeyExt`.

### For Recipients (Decryption Keys)

When a recipient wants to decrypt, they need a User Secret Key (USK):

1. **Client** reads the ciphertext header and identifies the recipient's `HiddenPolicy`.
2. **Client** calls `POST /v2/irma/start` with the required attributes from the policy.
3. **Recipient** scans the QR code and discloses the requested attributes.
4. **Client** retrieves the JWT via `GET /v2/irma/jwt/{token}`.
5. **Client** requests the USK via `GET /v2/irma/key/{timestamp}` with the JWT.
6. **PKG** validates the JWT, derives the KEM identity from the disclosed attributes + timestamp, and issues the USK using the master secret key.

## Hidden Policies

When a message is encrypted, the ciphertext header contains a **HiddenPolicy** for each recipient. This is a redacted version of the full policy that:

- **Shows** attribute types (so the recipient knows what to disclose)
- **Hides** attribute values (so other recipients can't see each other's identity details)
- **Optionally shows hints** for certain attribute types (e.g., last 4 characters of a phone number) to help recipients identify which entry is theirs

## API Key Authentication

As an alternative to Yivi sessions, the PKG also supports **API key authentication** for automated/server-side use cases. API keys are stored in PostgreSQL and carry pre-configured attributes:

```
Authorization: PG-API-<key>
```

The PKG looks up the key, extracts the associated attributes, and issues keys as if a Yivi session had been completed. This is useful for services that need to encrypt/decrypt without user interaction.

## Attribute Value Filtering

When building IRMA disclosure requests, the PKG filters out attributes with empty values. This ensures that:
- Attributes with a specified value require an exact match during disclosure
- Attributes without a value only check for existence (the IRMA server accepts any value)
