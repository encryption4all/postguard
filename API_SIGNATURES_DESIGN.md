# API-Based Signatures Design

## Overview

This document outlines the design for adding API-based signatures to PostGuard, enabling Business-to-Consumer (B2C) flows where systems/organizations can send end-to-end encrypted files without requiring human authentication via Yivi/IRMA.

**Scope**: API-based authentication applies **only to senders**, not recipients. Recipients continue using Identity-Based Encryption (IBE) with Yivi authentication.

## Motivation

### Current Limitation
The existing PostGuard system requires all senders to authenticate via Yivi, which is designed for human users. This prevents automated systems, backend services, or organizations from sending encrypted files programmatically.

### Use Cases
- Healthcare systems sending encrypted patient records to individuals
- Government agencies distributing encrypted documents to citizens
- Financial institutions transmitting secure statements to customers
- SaaS platforms sending encrypted data exports to users

## Architecture Changes

### High-Level Component Overview

```mermaid
graph TB
    subgraph "Senders"
        Human[Human User<br/>Yivi Auth]
        System[Organization/System<br/>API Key Auth]
    end

    subgraph "PKG Server"
        APIKeyStore[(API Key Store)]
        KeyIssuer[Key Issuer]
        YiviValidator[Yivi Validator]
        APIValidator[API Key Validator]
    end

    subgraph "Recipients"
        Recipient[Human Recipient<br/>Yivi Auth]
    end

    Human -->|Yivi Session| YiviValidator
    System -->|API Key| APIValidator

    YiviValidator --> KeyIssuer
    APIValidator --> KeyIssuer
    APIKeyStore --> APIValidator

    KeyIssuer -->|IBS Keys| Human
    KeyIssuer -->|IBS Keys| System

    Human -->|Encrypted File| Recipient
    System -->|Encrypted File| Recipient
    Recipient -->|Decrypt via Yivi| PKG
```

## Authentication Flows

### Current Flow: Identity-Based Signatures (Yivi)

```mermaid
sequenceDiagram
    participant Sender
    participant PKG
    participant Yivi

    Sender->>PKG: POST /v2/irma/start<br/>{con: [...attributes]}
    PKG->>Yivi: Create disclosure session
    Yivi-->>PKG: Session token + QR
    PKG-->>Sender: Session details

    Sender->>Sender: Display QR code
    Note over Sender: User scans QR<br/>with Yivi app

    Yivi->>Yivi: User discloses attributes
    Yivi->>PKG: Signed JWT with attributes

    Sender->>PKG: GET /v2/irma/jwt/{token}
    PKG-->>Sender: Signed JWT

    Sender->>PKG: POST /v2/irma/sign/key<br/>Authorization: Bearer {JWT}
    PKG->>PKG: Validate JWT signature
    PKG->>PKG: Extract disclosed attributes
    PKG->>PKG: Generate IBS keys from attributes
    PKG-->>Sender: {pubSignKey, privSignKey}

    Sender->>Sender: Sign message with IBS keys
```

### New Flow: API-Based Signatures

```mermaid
sequenceDiagram
    participant System
    participant PKG
    participant APIKeyStore

    System->>PKG: POST /v2/api/sign/key<br/>Authorization: Bearer {API_KEY}
    PKG->>PKG: Validate API key format
    PKG->>APIKeyStore: Lookup API key
    APIKeyStore-->>PKG: Key metadata<br/>{org_name, org_id, scope, expiry}

    alt Valid API Key
        PKG->>PKG: Check expiry & rate limits
        PKG->>PKG: Generate IBS keys from metadata
        PKG->>PKG: Log API key usage
        PKG-->>System: {pubSignKey, privSignKey,<br/>metadata}
    else Invalid/Expired Key
        PKG-->>System: 401 Unauthorized
    end

    System->>System: Sign message with IBS keys
    System->>Recipient: Send encrypted file
```

## API Key Management

### API Key Structure

```json
{
  "api_key_id": "apk_7x8y9z10...",
  "api_key_hash": "sha256(secret)",
  "organization": {
    "name": "Healthcare Provider Inc.",
    "id": "org_abc123",
    "contact_email": "security@healthprovider.com"
  },
  "metadata": {
    "description": "Patient records encryption service",
    "department": "IT Security"
  },
  "permissions": {
    "max_recipients_per_message": 100,
    "allowed_recipient_attributes": ["pbdf.gemeente.personalData.bsn"]
  },
  "rate_limits": {
    "requests_per_hour": 1000,
    "requests_per_day": 10000
  },
  "created_at": 1704643200,
  "expires_at": 1736179200,
  "revoked": false,
  "last_used_at": null
}
```

### API Key Format

**Bearer Token Format**:
```
pg_live_<base64url(32_random_bytes)>_<checksum>
```

Example: `pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9`

- Prefix indicates environment: `pg_live_`, `pg_test_`, `pg_dev_`
- 32 random bytes provide 256-bit entropy
- Checksum prevents typos (last 4 chars)

### Storage Options

#### Option A: SQLite Database (Recommended for MVP)
```sql
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    org_name TEXT NOT NULL,
    org_id TEXT NOT NULL,
    org_contact_email TEXT NOT NULL,
    metadata_json TEXT,
    permissions_json TEXT,
    rate_limits_json TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked INTEGER DEFAULT 0,
    last_used_at INTEGER,
    usage_count INTEGER DEFAULT 0
);

CREATE INDEX idx_key_hash ON api_keys(key_hash);
CREATE INDEX idx_org_id ON api_keys(org_id);
CREATE INDEX idx_expires_at ON api_keys(expires_at);
```

#### Option B: File-Based (TOML/JSON)
```toml
# api_keys.toml
[[keys]]
id = "apk_7x8y9z10"
key_hash = "sha256hash..."
org_name = "Healthcare Provider Inc."
org_id = "org_abc123"
created_at = 1704643200
expires_at = 1736179200
```

**Recommendation**: Use SQLite for production, file-based for development/testing.

### API Key Management CLI

Add new subcommands to `pg-pkg`:

```bash
# Generate a new API key
cargo run --release --bin pg-pkg api-key create \
  --org-name "Healthcare Provider Inc." \
  --org-id "org_abc123" \
  --contact "security@healthprovider.com" \
  --expires-in-days 365

# Output:
# API Key created successfully!
#
# Key ID: apk_7x8y9z10abc
# API Key: pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9
#
# ⚠️  Store this key securely! It will not be shown again.

# List all API keys
cargo run --release --bin pg-pkg api-key list

# Revoke an API key
cargo run --release --bin pg-pkg api-key revoke apk_7x8y9z10abc

# Show API key details (without revealing secret)
cargo run --release --bin pg-pkg api-key info apk_7x8y9z10abc

# Rotate an API key (generates new key, keeps metadata)
cargo run --release --bin pg-pkg api-key rotate apk_7x8y9z10abc
```

## API Endpoints

### New Endpoints for API-Based Signing

#### `POST /v2/api/sign/key`

Request signing keys using API authentication.

**Request Headers**:
```
Authorization: Bearer pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9
Content-Type: application/json
```

**Request Body**:
```json
{
  "pubSignId": [
    { "t": "api.organization.name" }
  ],
  "privSignId": [
    { "t": "api.organization.id" }
  ]
}
```

**Response** (200 OK):
```json
{
  "status": "SUCCESS",
  "pubSignKey": {
    "key": "base64_encoded_key...",
    "policy": {
      "ts": 1704643200,
      "con": [
        { "t": "api.organization.name", "v": "Healthcare Provider Inc." }
      ]
    }
  },
  "privSignKey": {
    "key": "base64_encoded_key...",
    "policy": {
      "ts": 1704643200,
      "con": [
        { "t": "api.organization.id", "v": "org_abc123" }
      ]
    }
  },
  "api_key_metadata": {
    "org_name": "Healthcare Provider Inc.",
    "org_id": "org_abc123",
    "key_id": "apk_7x8y9z10abc"
  }
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired API key
- `403 Forbidden`: API key revoked
- `429 Too Many Requests`: Rate limit exceeded
- `400 Bad Request`: Invalid request format

#### `POST /v2/api/auth/verify` (Optional)

Verify an API key without requesting signing keys (health check for integrations).

**Request Headers**:
```
Authorization: Bearer pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9
```

**Response** (200 OK):
```json
{
  "valid": true,
  "organization": "Healthcare Provider Inc.",
  "expires_at": 1736179200,
  "rate_limit": {
    "remaining_hourly": 998,
    "remaining_daily": 9856
  }
}
```

### Updated Parameter Endpoint

#### `GET /v2/parameters`

Add optional field indicating API signing support:

```json
{
  "format_version": 0,
  "public_key": "iizwD+mqUb7QqEFsCgruhaBM1hvOa9MiT52ZlQZ...",
  "features": {
    "api_based_signing": true,
    "api_version": "1.0"
  }
}
```

## Identity Representation in Signatures

### Attribute Namespace

Distinguish API-based identities from Yivi identities using a dedicated namespace:

**Yivi Identity** (existing):
```
pbdf.gemeente.personalData.fullname
irma-demo.sidn-pbdf.email.email
```

**API Identity** (new):
```
api.organization.name        → Organization display name
api.organization.id          → Unique organization identifier
api.organization.email       → Organization contact email
api.key.id                   → API key identifier (for audit)
api.key.created_at          → Key creation timestamp
```

### Policy Construction

When issuing signing keys for API-based authentication:

```rust
// Public signing identity (visible to everyone)
let pub_sign_id = Policy {
    timestamp: current_timestamp(),
    con: vec![
        Attribute::new("api.organization.name", Some("Healthcare Provider Inc."))
    ],
};

// Private signing identity (only visible to recipients)
let priv_sign_id = Policy {
    timestamp: current_timestamp(),
    con: vec![
        Attribute::new("api.organization.id", Some("org_abc123")),
        Attribute::new("api.key.id", Some("apk_7x8y9z10abc"))
    ],
};
```

## Wire Format Changes

### Backwards Compatibility

The existing wire format supports arbitrary attributes in signing policies, so **no wire format changes are required**. Recipients will see different attribute types in the sender's policy.

### Signature Verification

When a recipient decrypts a message:

```json
{
  "sender": {
    "public": {
      "ts": 1704643200,
      "con": [
        {
          "t": "api.organization.name",
          "v": "Healthcare Provider Inc."
        }
      ]
    },
    "private": {
      "ts": 1704643200,
      "con": [
        {
          "t": "api.organization.id",
          "v": "org_abc123"
        },
        {
          "t": "api.key.id",
          "v": "apk_7x8y9z10abc"
        }
      ]
    }
  }
}
```

Recipients can distinguish sender type by inspecting the attribute namespace:
- `api.*` → System/Organization sender
- `pbdf.*`, `irma-demo.*` → Human sender (Yivi)

## Security Considerations

### API Key Security

#### Storage
- **Server-side**: Store only SHA-256 hashes, never plaintext keys
- **Client-side**: Store in secure credential managers (e.g., HashiCorp Vault, AWS Secrets Manager)
- **Never** commit API keys to version control

#### Transmission
- Always use TLS/HTTPS for API key transmission
- Consider short-lived tokens for high-security scenarios

#### Key Rotation
- Support key rotation without service interruption
- Implement grace period where both old and new keys are valid
- Automatic expiry enforcement

### Rate Limiting

Implement per-API-key rate limits to prevent abuse:

```rust
struct RateLimiter {
    hourly_limit: u32,
    daily_limit: u32,
    current_hour_count: u32,
    current_day_count: u32,
    hour_reset_at: SystemTime,
    day_reset_at: SystemTime,
}
```

Use sliding window algorithm for accurate rate limiting.

### Audit Logging

Log all API key operations:

```rust
struct APIKeyAuditLog {
    timestamp: SystemTime,
    api_key_id: String,
    org_id: String,
    operation: APIKeyOperation, // SignKeyRequest, KeyVerification, etc.
    client_ip: IpAddr,
    user_agent: String,
    success: bool,
    error_code: Option<String>,
}
```

Retention: 90 days minimum, 1 year recommended.

### Permission Model

API keys should support scoped permissions:

```rust
enum APIKeyPermission {
    SignMessages,           // Can request signing keys
    EncryptForMultiple,     // Can encrypt for multiple recipients
    BulkOperations,         // Can perform batch operations
}

struct APIKeyPermissions {
    granted: Vec<APIKeyPermission>,
    max_recipients: usize,
    allowed_recipient_attributes: Vec<String>, // Whitelist of attribute types
}
```

### Revocation

Support immediate key revocation:
- Maintain in-memory cache of revoked keys (sync every 60s)
- Check revocation status on every authentication
- Webhook notifications for revocation events (optional)

## Implementation Phases

### Phase 1: Core Infrastructure (MVP)
- [ ] SQLite-based API key storage
- [ ] API key generation CLI (`pg-pkg api-key create`)
- [ ] API key management CLI (list, revoke, info)
- [ ] Basic authentication middleware for API keys
- [ ] `POST /v2/api/sign/key` endpoint
- [ ] Rate limiting (simple in-memory counter)

**Estimated effort**: 2-3 weeks

### Phase 2: Security Hardening
- [ ] Audit logging infrastructure
- [ ] Advanced rate limiting (sliding window, Redis-backed)
- [ ] Key rotation support
- [ ] Permission scoping
- [ ] Metrics and monitoring (Prometheus)

**Estimated effort**: 1-2 weeks

### Phase 3: Client Support
- [ ] Update `pg-cli` to support API key authentication
- [ ] WASM library support for API keys (optional)
- [ ] Example integrations (Python, Node.js SDK)
- [ ] Documentation and tutorials

**Estimated effort**: 1-2 weeks

### Phase 4: Advanced Features (Future)
- [ ] API key rotation webhooks
- [ ] Multi-tenancy support
- [ ] Organization management UI
- [ ] Usage analytics dashboard
- [ ] Integration with external IdPs (OAuth2)

## Code Structure

### New Files/Modules in `pg-pkg`

```
pg-pkg/
├── src/
│   ├── api_key/
│   │   ├── mod.rs           # Public API key module interface
│   │   ├── storage.rs       # Storage abstraction (SQLite/file)
│   │   ├── manager.rs       # CRUD operations for API keys
│   │   ├── validation.rs    # Key format validation, checksum
│   │   ├── rate_limit.rs    # Rate limiting logic
│   │   └── audit.rs         # Audit logging
│   ├── handlers/
│   │   ├── api_sign_key.rs  # POST /v2/api/sign/key
│   │   └── api_auth.rs      # POST /v2/api/auth/verify
│   ├── middleware/
│   │   └── api_auth.rs      # API key authentication middleware
│   └── cli/
│       └── api_key.rs       # CLI commands for API key management
```

### Key Abstractions

```rust
// Storage trait for flexibility
pub trait APIKeyStorage {
    fn create(&mut self, key: APIKey) -> Result<(), PKGError>;
    fn get_by_hash(&self, hash: &str) -> Result<Option<APIKey>, PKGError>;
    fn list(&self, org_id: Option<&str>) -> Result<Vec<APIKey>, PKGError>;
    fn revoke(&mut self, key_id: &str) -> Result<(), PKGError>;
    fn update_usage(&mut self, key_id: &str) -> Result<(), PKGError>;
}

// Rate limiter trait
pub trait RateLimiter {
    fn check_limit(&mut self, key_id: &str) -> Result<RateLimitStatus, PKGError>;
    fn record_request(&mut self, key_id: &str) -> Result<(), PKGError>;
}

// Audit logger trait
pub trait AuditLogger {
    fn log_event(&mut self, event: APIKeyAuditLog) -> Result<(), PKGError>;
    fn query_logs(&self, filter: AuditFilter) -> Result<Vec<APIKeyAuditLog>, PKGError>;
}
```

## Client Usage Examples

### Rust Client (pg-cli)

```rust
// In pg-cli: encrypt with API key
cargo run --release --bin pg-cli enc input.pdf output.pg \
    --api-key "pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9" \
    --recipient-bsn "123456789"
```

### HTTP API Direct Usage (cURL)

```bash
# Request signing keys
curl -X POST https://pkg.example.com/v2/api/sign/key \
  -H "Authorization: Bearer pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9" \
  -H "Content-Type: application/json" \
  -d '{
    "pubSignId": [{"t": "api.organization.name"}],
    "privSignId": [{"t": "api.organization.id"}]
  }'
```

### Python SDK (Future)

```python
from postguard import PostGuardClient, Policy, Attribute

client = PostGuardClient(
    pkg_url="https://pkg.example.com",
    api_key="pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9"
)

# Encrypt file for recipient
recipient_policy = Policy(
    timestamp=int(time.time()),
    attributes=[
        Attribute(type="pbdf.gemeente.personalData.bsn", value="123456789")
    ]
)

with open("input.pdf", "rb") as input_file:
    with open("output.pg", "wb") as output_file:
        client.encrypt(
            input_file,
            output_file,
            recipients={"recipient_id": recipient_policy}
        )
```

### Node.js SDK (Future)

```javascript
const { PostGuardClient } = require('@e4a/postguard');

const client = new PostGuardClient({
  pkgUrl: 'https://pkg.example.com',
  apiKey: 'pg_live_xK9mP2vL4nQ8rT6wY1zA5bD3cF7gH0jM_c4a9'
});

// Encrypt file
await client.encryptFile('input.pdf', 'output.pg', {
  recipients: {
    'recipient_id': {
      ts: Math.floor(Date.now() / 1000),
      con: [
        { t: 'pbdf.gemeente.personalData.bsn', v: '123456789' }
      ]
    }
  }
});
```

## Testing Strategy

### Unit Tests
- API key generation and validation
- Hash computation and verification
- Rate limiting logic
- Permission checking

### Integration Tests
- Full authentication flow with API keys
- Signing key issuance
- End-to-end encryption/decryption with API-signed messages
- Rate limit enforcement
- Key revocation

### Security Tests
- Brute force resistance (hash computation time)
- Invalid key format handling
- Expired key rejection
- Revoked key rejection
- SQL injection prevention (if using SQL storage)

## Migration Path

### For Existing Deployments

1. **Update PKG server** with API key support (backwards compatible)
2. **Create API keys** for organizations as needed
3. **Update client applications** to use API keys instead of Yivi for system-to-user flows
4. **Monitor usage** through audit logs and metrics

### Backwards Compatibility Guarantees

- Existing Yivi-based authentication continues to work unchanged
- Wire format remains compatible
- Recipients can decrypt messages from both API-based and Yivi-based senders
- No database migrations required for existing deployments

## Open Questions

1. **Multi-PKG deployments**: Should API keys be scoped to specific PKG instances, or support a federated model?

2. **Key recovery**: Should there be a secure key recovery mechanism for lost API keys, or force regeneration?

3. **Billing/quotas**: Should usage tracking support billing/quota enforcement, or just rate limiting?

4. **Webhook notifications**: Should the PKG support webhooks for key events (usage, expiry, revocation)?

5. **External IdP integration**: Should API keys support being issued via OAuth2/OIDC from external identity providers?

6. **Batch operations**: Should there be dedicated endpoints for bulk encryption operations?

## Appendix: Full Sequence Diagram (All Flows)

```mermaid
sequenceDiagram
    participant HumanSender as Human Sender<br/>(Yivi)
    participant SystemSender as System Sender<br/>(API Key)
    participant PKG
    participant YiviServer as Yivi Server
    participant Recipient

    Note over HumanSender,Recipient: Existing Flow (Yivi-based)

    HumanSender->>PKG: POST /v2/irma/start
    PKG->>YiviServer: Create session
    YiviServer-->>PKG: Session token
    PKG-->>HumanSender: QR code
    HumanSender->>YiviServer: Scan & disclose
    YiviServer->>PKG: JWT result
    HumanSender->>PKG: POST /v2/irma/sign/key
    PKG-->>HumanSender: Signing keys
    HumanSender->>HumanSender: Encrypt & sign
    HumanSender->>Recipient: Encrypted file

    Note over SystemSender,Recipient: New Flow (API-based)

    SystemSender->>PKG: POST /v2/api/sign/key<br/>Authorization: Bearer API_KEY
    PKG->>PKG: Validate API key
    PKG->>PKG: Check rate limits
    PKG->>PKG: Generate signing keys
    PKG-->>SystemSender: Signing keys + metadata
    SystemSender->>SystemSender: Encrypt & sign
    SystemSender->>Recipient: Encrypted file

    Note over Recipient: Decryption (same for both flows)

    Recipient->>PKG: POST /v2/irma/start
    PKG->>YiviServer: Create session
    YiviServer-->>PKG: Session token
    PKG-->>Recipient: QR code
    Recipient->>YiviServer: Scan & disclose
    YiviServer->>PKG: JWT result
    Recipient->>PKG: GET /v2/irma/key/{timestamp}
    PKG-->>Recipient: Decryption key
    Recipient->>Recipient: Decrypt & verify signature
    Recipient->>Recipient: Display sender info<br/>(Human or Organization)
```

## References

- [PostGuard Core Documentation](./pg-core/README.md)
- [PKG API Documentation](./pg-pkg/README.md)
- [Yivi Documentation](https://yivi.app/docs)
- [Identity-Based Cryptography](https://en.wikipedia.org/wiki/Identity-based_encryption)
