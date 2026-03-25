---
sidebar_position: 2
---

# WASM Bindings (pg-wasm)

The `@e4a/pg-wasm` package provides WebAssembly bindings for using PostGuard in browser environments. It supports both in-memory and streaming encryption/decryption using the Web Crypto API.

## Installation

```bash
npm install @e4a/pg-wasm
```

## API

### Encryption

#### `seal(mpk, options, plaintext): Uint8Array`

Encrypts a plaintext buffer in memory.

```typescript
import init, { seal } from '@e4a/pg-wasm';

await init();

const ciphertext = seal(masterPublicKey, {
  policy: {
    "recipient@example.com": {
      t: Math.floor(Date.now() / 1000),
      con: [
        { t: "pbdf.sidn-pbdf.email.email", v: "recipient@example.com" }
      ]
    }
  },
  pubSignKey: publicSigningKey,
  privSignKey: privateSigningKey, // optional
}, plaintext);
```

#### `sealStream(mpk, options, readable, writable): Promise<void>`

Encrypts a stream of data using the Web Streams API.

```typescript
import { sealStream } from '@e4a/pg-wasm';

await sealStream(
  masterPublicKey,
  sealOptions,
  readableStream,   // ReadableStream of plaintext
  writableStream     // WritableStream for ciphertext output
);
```

### Decryption

#### In-Memory

```typescript
import { Unsealer } from '@e4a/pg-wasm';

const unsealer = Unsealer.new(ciphertextBytes, verificationKey);

// Inspect which recipients the message is encrypted for
const recipients = unsealer.inspect_header();
// Returns: Map<string, HiddenPolicy>

// Decrypt for a specific recipient
const { plaintext, policy } = unsealer.unseal(recipientId, userSecretKey);
```

#### Streaming

```typescript
import { StreamUnsealer } from '@e4a/pg-wasm';

// Create unsealer from a readable stream
const unsealer = await StreamUnsealer.new(readableStream, verificationKey);

// Inspect header
const recipients = unsealer.inspect_header();
const senderPolicy = unsealer.public_identity();

// Decrypt to a writable stream
const verifiedPolicy = await unsealer.unseal(
  recipientId,
  userSecretKey,
  writableStream
);
```

### Types

#### `ISealOptions`

```typescript
interface ISealOptions {
  policy?: EncryptionPolicy;
  pubSignKey: ISigningKey;
  privSignKey?: ISigningKey;
  skipEncryption?: boolean;
}
```

#### `EncryptionPolicy`

A map of recipient IDs to their policies:

```typescript
type EncryptionPolicy = {
  [recipientId: string]: {
    t: number;  // Unix timestamp
    con: Array<{ t: string; v?: string }>;  // Conjunction of attributes
  }
};
```

## Integration with Yivi

In a browser application, you typically use the [Yivi JavaScript SDK](https://irma.app/docs/yivi-frontend/) to handle the disclosure sessions, then pass the resulting keys to pg-wasm for encryption/decryption.

### Example: Decryption Flow

```typescript
import init, { StreamUnsealer } from '@e4a/pg-wasm';

// 1. Initialize WASM
await init();

// 2. Parse ciphertext header
const unsealer = await StreamUnsealer.new(ciphertextStream, verificationKey);
const recipients = unsealer.inspect_header();

// 3. Start Yivi session to get USK
const response = await fetch(`${pkgUrl}/v2/irma/start`, {
  method: 'POST',
  body: JSON.stringify({ attr: recipientPolicy }),
});
const session = await response.json();

// ... user completes Yivi disclosure ...

// 4. Fetch USK with JWT
const jwt = await fetch(`${pkgUrl}/v2/irma/jwt/${token}`);
const usk = await fetch(`${pkgUrl}/v2/irma/key/${timestamp}`, {
  headers: { Authorization: `Bearer ${jwt}` },
});

// 5. Decrypt
const outputStream = new WritableStream({ /* ... */ });
const senderPolicy = await unsealer.unseal(recipientId, usk, outputStream);
```

## Building from Source

```bash
cd pg-wasm
wasm-pack build --release -d pkg/ --out-name index --scope e4a --target bundler
```

For web target (without a bundler):

```bash
wasm-pack build --release -d pkg/ --out-name index --scope e4a --target web
```
