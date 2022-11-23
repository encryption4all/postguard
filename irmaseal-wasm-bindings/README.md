## IRMAseal wasm bindings

This package contains automatically generated WebAssembly bindings to call into
the IRMAseal rust library from javascript. This library has been designed to
run in a browser via a bundler.

The `ReadableStream` and `WritableStream` Web APIs are required. Most notably,
`WritableStream` is not supported on Firefox until version 100, see
[WritableStream](https://developer.mozilla.org/en-US/docs/Web/API/WritableStream).

If not available, please consider using a polyfill, see
[web-streams-polyfill](https://www.npmjs.com/package/web-streams-polyfill).

## Usage

### Encryption

```javascript
// Retrieve the public key from PKG API:
const resp = await fetch(`${url}/v2/parameters`);
const pk = await resp.json().then((r) => r.publicKey);

// Load the WASM module.
const module = await import("@e4a/irmaseal-wasm-bindings");

// We provide the policies which we want to use for encryption.
const policies = {
  recipient_1: {
    ts: Math.round(Date.now() / 1000),
    con: [
      { t: "pbdf.sidn-pbdf.email.email", v: "john.doe@example.com" },
      { t: "pbdf.gemeente.personalData.fullname", v: "John" },
    ],
  },
};

// The following call reads data from a `ReadableStream` and seals it into `WritableStream`.
// Make sure that only chunks of type `Uint8Array` are enqueued to `readable`.
await module.seal(pk, policies, readable, writable);
```

### Decryption

```javascript
// We assume we know the identifier of the recipient.

// Load the WASM module.
const module = await import("@e4a/irmaseal-wasm-bindings");

// Start reading from the IRMAseal bytestream. This will read
// the metadata up until the actual payload. The stream is still locked.
const unsealer = await module.Unsealer.new(readable);

// Retrieve the hidden (purged of attribute values) policy of this recipient.
const hidden = unsealer.get_hidden_policies();

// In this case it will yield:
// {
//  'recipient_1': {                                  // recipient identifier
//    ts: 1643634276,                                 // timestamp
//    con: [                                          // conjunction of attributes
//      { t: "pbdf.sidn-pbdf.email.email", v: "" },   // type/value pairs
//      { t: "pbdf.gemeente.personalData.fullname", v: "" },
//    ],
//  },
// }

// The disclosed values have to match with the values used for encryption.
// Note that we do not include a timestamp here.
// Since the personalData credential is singleton, we just ask the value and decryption will
// fail in the next step if it is not "John".
const keyRequest = {
  con: [
    { t: "pbdf.sidn-pbdf.email.email", v: "john.doe@xample.com" },
    { t: "pbdf.gemeente.personalData.fullname" },
  ],
};

const timestamp = hidden["recipient_1"].ts;

// Create a session to retrieve a User Secret Key (USK) for the guessed identity.
// In this example we use the irma frontend packages,
// see [`irma-frontend-packages`](https://irma.app/docs/irma-frontend/).
const session = {
  url,
  start: {
    url: (o) => `${o.url}/v2/request/start`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(keyRequest),
  },
  result: {
    url: (o, { sessionToken }) => `${o.url}/v2/request/jwt/${sessionToken}`,
    parseResponse: (r) => {
      return r
        .text()
        .then((jwt) =>
          fetch(`${pkg}/v2/request/key/${timestamp.toString()}`, {
            headers: {
              Authorization: `Bearer ${jwt}`,
            },
          })
        )
        .then((r) => r.json())
        .then((json) => {
          if (json.status !== "DONE" || json.proofStatus !== "VALID")
            throw new Error("not done and valid");
          return json.key;
        })
        .catch((e) => console.log("error: ", e));
    },
  },
};

var irma = new IrmaCore({ debugging: true, session });
irma.use(IrmaClient);
irma.use(IrmaPopup);
const usk = await irma.start();

// Unseal the contents of the IRMAseal packet, writing the plaintext to a `WritableStream`.
await unsealer.unseal("recipient_1", usk, writable);
```

### Leveraging Web Workers

Since `ReadableStream` and `WritableStream` are
[transferable](https://developer.mozilla.org/en-US/docs/Glossary/Transferable_objects),
it is advised to perform the sealing and unsealing in a [Web
Worker](https://developer.mozilla.org/en-US/docs/Web/API/Worker).

## Building the package from the crate

### Prerequisites

Make sure the latest version of wasm-pack is installed:

```
cargo install --git https://github.com/rustwasm/wasm-pack.git
```

### Building

To build the bindings package, run:

```
wasm-pack build --release -d pkg/ --out-name index --scope e4a --target bundler
```

Note that this includes a scope.

### Testings

To test the bindings package, run:

```
wasm-pack test --chrome --headless
```

### Publishing (on npm)

The following command publishes the wasm module as a package on npm:

```
wasm-pack publish
```
