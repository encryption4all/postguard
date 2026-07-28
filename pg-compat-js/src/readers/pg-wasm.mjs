//! A published `@e4a/pg-wasm` as a reader.
//!
//! This is the layer that owns the container format on the JS side: `pg-js`
//! wraps it, the Outlook add-in and cryptify reach it through `pg-js`, and both
//! of its unsealers are part of the wire surface. It is also the only JS reader
//! that opens a memory-mode container, so a break there is only visible here.

import { readFile } from 'node:fs/promises';

/**
 * @param {{version: string, specifier: string}} pin
 *   `version` as published on npm; `specifier` the npm alias it is installed
 *   under, so several versions can coexist in one `node_modules`
 * @returns {object} a reader (see `../readers.mjs` for the contract)
 */
export function pgWasmReader({ version, specifier }) {
  return {
    id: `@e4a/pg-wasm@${version}`,
    package: '@e4a/pg-wasm',
    version,
    specifier,
    cannotOpen: {},
    privateSignatureVisible: true,

    async load() {
      // The package's default entry is the bundler target, which does
      // `import * as wasm from "./index_bg.wasm"` — Node cannot resolve that
      // without --experimental-wasm-modules. The web target takes the module
      // bytes as an argument instead, so it runs under plain Node. The wasm
      // file is not in the package's `exports`, so resolve the glue and read
      // its sibling rather than resolving the wasm directly.
      const glue = `${specifier}/web`;
      const module = await import(glue);
      await module.default({
        module_or_path: await readFile(new URL('index_bg.wasm', import.meta.resolve(glue))),
      });
      return module;
    },

    async open(module, { mode, ciphertext, verifyingKey, recipientId, usk }) {
      if (mode === 'memory') return openMemory(module, { ciphertext, verifyingKey, recipientId, usk });
      if (mode === 'stream') return openStream(module, { ciphertext, verifyingKey, recipientId, usk });
      throw new Error(`unknown mode ${mode}`);
    },
  };
}

// `unseal()` takes ownership of the unsealer: the generated glue hands the
// pointer to wasm and nulls it on the way in. Calling `free()` afterwards is a
// double free, reported as `null pointer passed to rust` — which reads exactly
// like a broken container. So nothing here frees an unsealer it has unsealed
// with; the case process is short-lived and wasm-bindgen's FinalizationRegistry
// covers the paths that throw first.
async function openMemory(module, { ciphertext, verifyingKey, recipientId, usk }) {
  const unsealer = await module.Unsealer.new(ciphertext, verifyingKey);
  const recipients = [...unsealer.inspect_header().keys()];
  const [plaintext, identity] = await unsealer.unseal(recipientId, usk);
  return { plaintext, identity, recipients };
}

async function openStream(module, { ciphertext, verifyingKey, recipientId, usk }) {
  // A fresh ReadableStream per open: the unsealer locks the one it is handed
  // for as long as it lives.
  const readable = new ReadableStream({
    start(controller) {
      controller.enqueue(ciphertext);
      controller.close();
    },
  });
  const chunks = [];
  const writable = new WritableStream({
    write(chunk) {
      chunks.push(chunk);
    },
  });

  const unsealer = await module.StreamUnsealer.new(readable, verifyingKey);
  const recipients = [...unsealer.inspect_header().keys()];
  const identity = await unsealer.unseal(recipientId, usk, writable);
  return { plaintext: concat(chunks), identity, recipients };
}

function concat(chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
