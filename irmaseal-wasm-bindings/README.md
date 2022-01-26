## IRMAseal wasm bindings

This package contains automatically generated javascript wasm-bindgen bindings
to call into the IRMAseal rust library from javacript.

## Usage

```javascript
// Retrieve the public key from PKG API:
const resp = await fetch(`${url}/v2/parameters`)
const params = JSON.parse(await resp.text())

// Load the WASM module.
const module = await import('@e4a/irmaseal-wasm-bindings')

// We provide the policies which we want to use for encryption.
const policies = {
  'recipient_1': {
    t: Math.round(Date.now() / 1000),
    c: [
      { t: 'pbdf.sidn-pbdf.email.email', v: 'john.doe@example.com' },
      { t: 'pbdf.gemeente.personalData.fullname', v: 'John' },
    ],
  },
}

// The following call reads data from a `ReadableStream` and encrypts into `WritableStream`.
await seal(
  client.params.public_key,
  policies,
  readable,
  writable
)
```

### Decryption
```javascript
// We assume we know the identifier of the recipient.
// Load the WASM module.
const module = await import('@e4a/irmaseal-wasm-bindings')

// Start reading from the IRMAseal packet.
const unsealer = await new module.Unsealer(readable, 'recipient_1')

// Retrieve the hidden (purged of attribute values) policy of this recipient.
const hidden = unsealer.get_hidden_policy()

// In this case it will yield:
// [{ t: 'pbdf.sidn-pbdf.email.email', v: '' },
//  { t: 'pbdf.gemeente.personalData.fullname', v: '' }]

// Guess the values of each of attribute right.
const identity = {
  con: [
    { t: 'pbdf.sidn-pbdf.email.email', v: 'john.doexample.com' },
    { t: 'pbdf.gemeente.personalData.fullname', v: 'John' },
  ],
}

// Create a session to retrieve a UserSecretKey (USK) for the guessed identity.
const session = createPKGSession(identity, hidden.t)
var irma = new IrmaCore({ debugging: true, session })
irma.use(IrmaClient)
irma.use(IrmaPopup)

// Retrieve the USK.
const usk = await irma.start()

// Unseal the contents of the IRMAseal packet, writing the plain to a `WritableStream`.
await unsealer.unseal(usk, writable)
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

### Publishing

```
wasm-pack publish
```
