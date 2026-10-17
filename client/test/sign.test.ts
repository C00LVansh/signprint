import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Counter } from "../src/nonce.ts";
import { signRequest } from "../src/sign.ts";

const vectors = JSON.parse(readFileSync(new URL("../../testvectors/wire.json", import.meta.url), "utf8"));

async function session(tab: number, start: number) {
  const raw = Uint8Array.from(vectors.mac_key_hex.match(/../g).map((h: string) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return { token: vectors.signatures[0].input.keyid, key, counter: new Counter(tab, BigInt(start)) };
}

for (const name of ["post json", "uppercase host, default port, encoded path"]) {
  test(`signRequest reproduces vector: ${name}`, async () => {
    const v = vectors.signatures.find((s: { name: string }) => s.name === name);
    const { input, expect } = v;
    const [tab, ctr] = input.nonce.split(".");
    const url = `${input.https ? "https" : "http"}://${input.authority}${input.path}${input.query === null ? "" : "?" + input.query}`;
    const body = input.body_b64 === null ? null : Uint8Array.from(atob(input.body_b64), (c) => c.charCodeAt(0));

    const headers = await signRequest(input.method, url, body, await session(parseInt(tab, 16), Number(ctr)), input.created * 1000);

    assert.equal(headers["signature-input"], expect.signature_input);
    assert.equal(headers.signature, expect.signature);
    assert.equal(headers["content-digest"], expect.content_digest ?? undefined);
  });
}

test("empty body is treated as no body", async () => {
  const h = await signRequest("POST", "https://shop.example/x", new Uint8Array(), await session(1, 0));
  assert.equal(h["content-digest"], undefined);
  assert.ok(!h["signature-input"].includes("content-digest"));
});

test("GET with a body is refused", async () => {
  await assert.rejects(signRequest("GET", "https://shop.example/x", new Uint8Array([1]), await session(1, 0)), TypeError);
});

test("counter advances and clock offset applies", async () => {
  const s = { ...(await session(0xabc, 5)), clockOffsetMs: 10_000 };
  const a = await signRequest("GET", "https://shop.example/", null, s, 1_000_000_000_000);
  const b = await signRequest("GET", "https://shop.example/", null, s, 1_000_000_000_000);
  assert.match(a["signature-input"], /nonce="00000abc\.5"/);
  assert.match(b["signature-input"], /nonce="00000abc\.6"/);
  assert.match(a["signature-input"], /created=1000000010;/);
});
