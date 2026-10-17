import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { fromBase64, fromBase64Url, toBase64 } from "../src/b64.ts";
import { canonicalAuthority, canonicalPath, canonicalQuery } from "../src/canonical.ts";
import { contentDigest, deriveSessionKey, mac } from "../src/crypto.ts";
import { headerValues, signatureBase } from "../src/signature.ts";

const vectors = JSON.parse(readFileSync(new URL("../../testvectors/wire.json", import.meta.url), "utf8"));
const subtle = globalThis.crypto.subtle;

function hexBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

async function hmacKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

for (const v of vectors.signatures) {
  test(`signature: ${v.name}`, async () => {
    const { input, expect } = v;

    const authority = canonicalAuthority(input.authority, input.https);
    const path = canonicalPath(input.path);
    const query = canonicalQuery(input.query);
    assert.equal(authority, expect.authority);
    assert.equal(path, expect.path);
    assert.equal(query, expect.query);

    const digest = input.body_b64 === null ? undefined : await contentDigest(fromBase64(input.body_b64));
    assert.equal(digest ?? null, expect.content_digest);

    const params = { created: input.created, keyid: input.keyid, nonce: input.nonce };
    const base = signatureBase({ method: input.method, authority, path, query, contentDigest: digest }, params);
    assert.equal(base, expect.signature_base);

    const tag = await mac(await hmacKey(hexBytes(vectors.mac_key_hex)), base);
    const headers = headerValues(params, digest !== undefined, tag);
    assert.equal(headers.signatureInput, expect.signature_input);
    assert.equal(headers.signature, expect.signature);
  });
}

for (const [i, v] of vectors.ecdh.entries()) {
  test(`ecdh session key ${i} matches the server`, async () => {
    const clientPrivate = await subtle.importKey("jwk", v.client_jwk, { name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveKey",
    ]);
    const key = await deriveSessionKey(clientPrivate, fromBase64Url(v.server_public_raw));

    assert.equal(key.extractable, false);
    await assert.rejects(subtle.exportKey("raw", key));

    assert.equal(toBase64(await mac(key, v.base)), v.mac_b64);
  });
}
