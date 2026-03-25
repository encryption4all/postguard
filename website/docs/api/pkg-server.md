---
sidebar_position: 1
---

# PKG Server API

The Private Key Generator (PKG) server (`pg-pkg`) exposes an HTTP API for parameter retrieval, Yivi session management, and key issuance.

## Base URL

By default the server listens on `http://localhost:8080`. Configure via CLI flags.

## Endpoints

### Get Public Parameters

```
GET /v2/parameters
```

Returns the master public key (IBE) used by senders to encrypt messages.

**Response**: `PublicKey` (JSON, base64-encoded)

---

### Get Verification Key

```
GET /v2/sign/parameters
```

Returns the public verification key (IBS) used to verify sender signatures.

**Response**: `VerifyingKey` (JSON, base64-encoded)

---

### Start Yivi Session

```
POST /v2/irma/start
```

Initiates a Yivi disclosure session for obtaining either decryption keys or signing keys.

**Request Body**:
```json
{
  "attr": {
    "recipient@example.com": {
      "t": 1234567890,
      "con": [
        {"t": "pbdf.sidn-pbdf.email.email", "v": "recipient@example.com"}
      ]
    }
  }
}
```

**Response**: IRMA session package (contains QR code data for the Yivi app)

---

### Retrieve Session JWT

```
GET /v2/irma/jwt/{token}
```

Retrieves the signed JWT from the IRMA server after a successful disclosure session.

**Path Parameters**:
- `token` — The IRMA session token from the start response

**Response**: JWT string signed by the IRMA server

---

### Get Decryption Key (USK)

```
GET /v2/irma/key/{timestamp}
```

Issues a User Secret Key for decryption. Requires a valid JWT from a completed Yivi session.

**Path Parameters**:
- `timestamp` — The timestamp from the encryption policy

**Headers**:
- `Authorization: Bearer <jwt>` — JWT from the IRMA server

**Response**: `UserSecretKey` (JSON, base64-encoded)

---

### Get Signing Keys

```
POST /v2/irma/sign/key
```

Issues signing keys (public and optional private) for a sender.

**Headers**:
- `Authorization: Bearer <jwt>` — JWT from the IRMA server, **or**
- `Authorization: PG-API-<key>` — API key for automated access

**Request Body**:
```json
{
  "pubSignId": [
    {"t": "pbdf.gemeente.personalData.fullname"}
  ],
  "privSignId": [
    {"t": "pbdf.sidn-pbdf.email.email"}
  ]
}
```

**Response**: `SigningKeyResponse` containing public and optional private signing keys

## Authentication

The PKG supports two authentication methods:

### JWT (Yivi Sessions)
After a successful Yivi disclosure, the IRMA server issues a signed JWT containing the disclosed attributes. Pass this as a Bearer token.

### API Keys
For server-to-server or automated use cases, API keys can be configured in the PostgreSQL database. These carry pre-configured attributes and bypass the need for interactive Yivi sessions.

```
Authorization: PG-API-<your-api-key>
```

## Running the Server

```bash
# Generate master keys (run once)
cargo run --release --bin pg-pkg gen

# Start the server
cargo run --release --bin pg-pkg server \
  -t <irma_server_token> \
  -i <irma_server_url> \
  -d <postgres_connection_string>
```

### Docker

```bash
docker build -t postguard-pkg .
docker run -p 8080:8080 postguard-pkg server \
  -t <irma_token> \
  -i <irma_url> \
  -d <postgres_url>
```
