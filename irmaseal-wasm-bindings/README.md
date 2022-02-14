## IRMAseal wasm bindings

This package contains automatically generated javascript wasm-bindgen bindings
to call into the IRMAseal rust library from javacript. The `ReadableStream`
bytestream and `WritableStream` Web APIs are required. If not available, make
sure to polyfill them, see
[web-streams-polyfill](https://www.npmjs.com/package/web-streams-polyfill).

## Usage

### Encryption

```javascript
// Retrieve the public key from PKG API:
const resp = await fetch(`${url}/v2/parameters`);
const pk = await resp.json().then((r) => r.public_key);

// Load the WASM module.
const module = await import("@e4a/irmaseal-wasm-bindings");

// We provide the policies which we want to use for encryption.
const policies = {
  recipient_1: {
    t: Math.round(Date.now() / 1000),
    c: [
      { t: "pbdf.sidn-pbdf.email.email", v: "john.doe@example.com" },
      { t: "pbdf.gemeente.personalData.fullname", v: "John" },
    ],
  },
};

// The following call reads data from a `ReadableStream` and seals it into `WritableStream`.
await module.seal(pk, policies, readable, writable);
```

### Decryption

```javascript
// We assume we know the identifier of the recipient.
// Load the WASM module.
const module = await import("@e4a/irmaseal-wasm-bindings");

// Start reading from the IRMAseal bytestream. This will read
// the metadata up until the actual payload. The stream is still locked.
const unsealer = await new module.Unsealer(readable);

// Retrieve the hidden (purged of attribute values) policy of this recipient.
const hidden = unsealer.get_hidden_policy();

// In this case it will yield:
// {
//  'recipient_1': {                                  // recipient identifier
//    t: 1643634276,                                  // timestamp
//    c: [                                            // conjunction of attributes
//      { t: "pbdf.sidn-pbdf.email.email", v: "" },   // type/value pairs
//      { t: "pbdf.gemeente.personalData.fullname", v: "" },
//    ],
//  },
// }

// Guess the values of each of attribute right (note: we do no include the timestamp here).
const identity = {
  con: [
    { t: "pbdf.sidn-pbdf.email.email", v: "john.doe@xample.com" },
    { t: "pbdf.gemeente.personalData.fullname", v: "John" },
  ],
};

const timestamp = hidden["recipient_1"].t;

// Create a session to retrieve a User Secret Key (USK) for the guessed identity.
// In this example we use the irma frontend packages,
// see [`irma-frontend-packages`](https://irma.app/docs/irma-frontend/).
const session = {
  session: {
    url, // PKG URL
    start: {
      url: (o) => `${o.url}/v2/request`,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(identity),
    },
    result: {
      url: (o, { sessionToken }) =>
        `${o.url}/v2/request/${sessionToken}/${timestamp.toString()}`,
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
