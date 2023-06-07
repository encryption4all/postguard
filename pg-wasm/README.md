## pg-wasm

This package contains automatically generated WebAssembly bindings to call into
the PostGuard Rust library from Javascript or Typescript. This library has been
configured to run in a browser via a bundler.

The `ReadableStream` and `WritableStream` Web APIs are required. Most notably,
`WritableStream` is not supported on Firefox until version 100, see
[WritableStream](https://developer.mozilla.org/en-US/docs/Web/API/WritableStream).

If not available, please consider using a polyfill, see
[web-streams-polyfill](https://www.npmjs.com/package/web-streams-polyfill).

## Usage

See [the examples repo](https://github.com/encryption4all/pg-example)
for working examples.

### Fetching keys

Fetching keys from the PKG (for both decryption/signing) is easiest using the
Yivi frontend packages and a custom `session` field.

```javascript
// The URL of the PKG.
const PKG_URL = "...";

const KeySorts = {
  Encryption: "key",
  Signing: "sign/key",
};

async function fetchKey(sort, keyRequest, timestamp = undefined) {
  const session = {
    url: PKG_URL,
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
            fetch(
              `${PKG_URL}/v2/irma/${sort}${
                timestamp ? "/" + timestamp.toString() : ""
              }`,
              {
                headers: {
                  Authorization: `Bearer ${jwt}`,
                },
              }
            )
          )
          .then((r) => r.json())
          .then((json) => {
            if (json.status !== "DONE" || json.proofStatus !== "VALID")
              throw new Error("not done and valid");
            return json.key;
          });
      },
    },
  };

  const yivi = new YiviCore({ debugging: false, session });
  yivi.use(YiviClient);
  yivi.use(YiviPopup);

  return yivi.start();
}
```

### Encryption

```javascript
// Load the WASM module.
const { sealStream } = await import("@e4a/pg-wasm");

// Retrieve the public key from PKG API:
const resp = await fetch(`${url}/v2/parameters`);
const pk = await resp.json().then((r) => r.publicKey);

// We provide the policies which we want to use for encryption.
const policy = {
  Bob: {
    ts: Math.round(Date.now() / 1000),
    con: [{ t: "irma-demo.sidn-pbdf.email.email", v: "bob@example.com" }],
  },
};

// We provide the policies which we want to sign with.

// This policy is visible to everyone.
const pubSignPolicy = {
  con: [{ t: "irma-demo.gemeente.personalData.fullname", v: "Alice" }],
};

// This policy is only visible to recipients.
const privSignPolicy = {
  con: [{ t: "irma-demo.gemeente.personalData.bsn", v: "1234" }],
};

// We retrieve keys for these policies.
let pubSignKey = await fetchKey(KeySorts.Signing, pubSignPolicy);
let privSignKey = await fetchKey(KeySorts.Signing, privSignPolicy);

const sealOptions = {
  policy,
  pubSignKey,
  privSignKey,
};

// The following call reads data from a `ReadableStream` and seals it into `WritableStream`.
// Make sure that only chunks of type `Uint8Array` are enqueued to `readable`.
await sealStream(pk, sealOptions, readable, writable);
```

### Decryption

```javascript
// Load the WASM module.
const { StreamUnsealer } = await import("@e4a/pg-wasm");

// Retrieve to global verification key.
const vk = await fetch(`${PKG_URL}/v2/sign/parameters`)
  .then((r) => r.json())
  .then((j) => j.publicKey);

// Start reading from the ReadableStream. This will read
// the metadata up until the actual payload. The stream is still locked.
const unsealer = await StreamUnsealer.new(readable, vk);

// Retrieve the recipients (and their respective policies) from the header.
const recipients = unsealer.inspect_header();

// In this case it will yield:
// {
//  'Bob': {                                              // recipient identifier
//    ts: 1643634276,                                     // timestamp
//    con: [                                              // conjunction of attributes
//      { t: "irma-demo.sidn-pbdf.email.email", v: "" },  // type/value pairs
//    ],
//  },
// }

// The disclosed values have to match with the values used for encryption.
// Note that we do not include a timestamp here.
const keyRequest = {
  con: [{ t: "irma-demo.sidn-pbdf.email.email", v: "Bob" }],
};

const timestamp = recipients.get("Bob").ts;
const usk = await fetchKey(KeySorts.Encryption, keyRequest, timestamp);

// Unseal the contents, writing the plaintext to a `WritableStream`.
let sender = await unsealer.unseal("Bob", usk, writable);

// console.log(sender) will give the policy that was used to sign:
// {
//   "public": {
//     "ts": 1680531126,
//     "con": [
//       {
//         "t": "irma-demo.gemeente.personalData.fullname",
//         "v": "Alice"
//       }
//     ]
//   },
//   "private": {
//     "ts": 1680531130,
//     "con": [
//       {
//         "t": "irma-demo.gemeente.personalData.bsn",
//         "v": "1234"
//       }
//     ]
//   }
// }
```

### Encrypting `Uint8Array`

Encrypting and decrypting `Uint8Array` works similar as the example above. The
WASM module also exports `seal` and `Unsealer`, which can be used for this. The
function `seal` returns a new `Uint8Array`. The `Unsealer.unseal` method
returns an array `[plain, policy]`, where `plain` is a `Uint8Array` containing
the plaintext and `policy` is an object containing the sender's signing policy.

### Leveraging Web Workers

Since `ReadableStream` and `WritableStream` are
[transferable](https://developer.mozilla.org/en-US/docs/Glossary/Transferable_objects),
it is advised to perform the sealing and unsealing off the main thread, e.g.,
in a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Worker).
[Comlink](https://github.com/GoogleChromeLabs/comlink) can be a useful library
to communicate between threads.

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
