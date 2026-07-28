//! The PKG endpoints `@e4a/pg-js` fetches on its decrypt path, served from the
//! sample set.
//!
//! `pg-js` is an SDK for a deployment: it takes a `pkgUrl` and fetches the
//! verifying key and the recipient's user secret key from it, because in the
//! field the USK only exists after a Yivi disclosure. The gate has neither a
//! PKG nor a Yivi app, but it does have both keys on disk — the sealer writes
//! them shaped like the responses of the two endpoints on purpose
//! (`pg-compat/README.md`).
//!
//! So this is not a PKG and does not pretend to be one: no session, no proof,
//! no signing keys, nothing an encrypt path would need. It hands back the two
//! files the artifact already carries, which is what lets the published SDK's
//! real decrypt path run unmodified against HEAD-sealed bytes. Swapping in a
//! mock unsealer instead would test our mock rather than the wire format.

import { createServer } from 'node:http';

/**
 * `GET /v2/sign/parameters` answers with the verifying key, and
 * `GET /v2/irma/key/<timestamp>` with the user secret key of the recipient
 * named by the bearer token. Where a deployment passes a Yivi JWT, the gate
 * passes the recipient id from the manifest — the stub is the only thing
 * reading it, and it has no session state to look up.
 *
 * @param {{verifyingKey: string, usks: Record<string, string>}} artifacts
 *   raw JSON of `vk.json` and of each `usk-<id>.json`, keyed by recipient id
 * @returns {Promise<{url: string, close: () => Promise<void>}>}
 */
export async function startPkgStub({ verifyingKey, usks }) {
  const server = createServer((req, res) => {
    const json = (body) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(body);
    };

    const { pathname } = new URL(req.url, 'http://localhost');
    if (pathname === '/v2/sign/parameters') {
      json(verifyingKey);
      return;
    }

    if (/^\/v2\/irma\/key\/\d+$/.test(pathname)) {
      const recipient = (req.headers.authorization ?? '').replace(/^Bearer /, '');
      if (Object.hasOwn(usks, recipient)) {
        json(usks[recipient]);
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: `no user secret key for recipient ${recipient}` }));
      return;
    }

    // Anything else means the SDK's decrypt path changed shape and the gate is
    // no longer exercising what it thinks it is. Say which route was asked for.
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: `the wire-compat PKG stub does not serve ${pathname}` }));
  });

  // Loopback only, and a port the kernel picks, so several case processes can
  // run at once without agreeing on anything.
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
