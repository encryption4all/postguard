# pg-pkg

This crate contains the PostGuard PKG service HTTP API. The crate is powered by
the [actix-web](https://actix.rs/) framework. The PKG communicates with an IRMA
server to validate identities before issuing decryption or signing keys. The
IRMA server is required to have a JWT private key configured, see [signed
session
results](https://irma.app/docs/irma-server/#signed-jwt-session-results).

## Usage

For its usage, see the help:

```
irmaseal-pkg --help
```

## API description

### `GET /v2/parameters`

Retrieves the public encryption parameters. This includes a base64-encoded master public
key.

Example response:

```JSON
{
  "format_version": 0,
  "public_key": "iizwD+mqUb7QqEFsCgruhaBM1hvOa9MiT52ZlQZ..."
}
```

### `GET /v2/sign/parameters`

Retrieves the public signing parameters. This includes a base64-encoded master public
key, used for verification.

### `POST /v2/irma/start`

Starts a session to retrieve either a decryption key or a signing key IRMA. The
request must include a JSON body containing a `KeyRequest`. As an example, we
want to request a key for someone named Alice. Note that since this credential
is from the demo scheme, anyone can retrieve such a credential. We also request
for the authentication to be valid for 1 day, or 86400 seconds, which is also
the maximum. By default the authentication is valid for 5 minutes. If the
requested validity exceeds the maximum a `401` (`BAD REQUEST`) is returned.

```JSON
{
  "con": [{ "t": "irma-demo.gemeente.personalData.fullname", "v": "Alice" }],
  "validity": 86400
}
```

The response looks like a typical IRMA disclosure session package:

```JSON
{
  "sessionPtr": {
    "u": "https://<irmaserver>/irma/session/5Al4uk1CePkRX5BTn4e2",
    "irmaqr": "disclosing"
  },
  "token": "oUyZncomdCoOyWKkZgww"
}
```

### `GET /v2/irma/jwt/{token}`

Retrieves a JSON Web Token (JWT) for an ongoing or finished session. Returns a
JWT using the `text/plain` content type. The JWT is an IRMA session result
signed by the IRMA server. This token can subsequently be used as HTTP
Authorization Header to retrieve USKs, see below.

### `GET /v2/irma/key/{timestamp}`

Retrieves a User Secret Key (USK) for a ciphertext with the given timestamp.
The request must include a HTTP Authorization header `Authorization: Bearer <JWT>`.

If the JWT is a valid JWT signed by the IRMA server, the result will look as
follows:

```JSON
{
  "status": "DONE",
  "proofStatus": "VALID",
  "key": "gdnZOyi2DGTzWv+Pq..."
}
```

The `status` field will always be included. The `proofStatus` and `key` values
are optional and depend on the JWT. A key is included if and only if the proof
was valid and all the claimed attributes were present. A key is derived from these attributes.

### `GET /v2/irma/sign/key`

Retrieves a signing key. The request must include a HTTP Authorization header
`Authorization: Bearer <JWT>`.

The response looks similar as `GET /v2/irma/key/{timestamp}`, except the key is
a signing key.
