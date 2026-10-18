import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { fromBase64Url } from "../src/b64.ts";
import { leadingZeroBits, powHash, solvePow } from "../src/pow.ts";

const v = JSON.parse(readFileSync(new URL("../../testvectors/pow.json", import.meta.url), "utf8"));

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

test("argon2id hashes match the Rust side", async () => {
  const id = fromBase64Url(v.id);
  for (const h of v.hashes) {
    const got = await powHash(id, h.index, h.nonce, v.params.memory_kib, v.params.iterations);
    assert.equal(hex(got), h.hash_hex, `index ${h.index} nonce ${h.nonce}`);
  }
});

test("solver finds the same first solutions", async () => {
  const nonces = await solvePow({ ticket: "x", id: v.id, expires_at: 0, ...v.params });
  assert.deepEqual(nonces, v.solution);
});

test("leading zero bits", () => {
  assert.equal(leadingZeroBits(new Uint8Array([0, 0, 0x10, 0xff])), 19);
  assert.equal(leadingZeroBits(new Uint8Array([0x80])), 0);
  assert.equal(leadingZeroBits(new Uint8Array([0, 0])), 16);
  assert.equal(leadingZeroBits(new Uint8Array([1])), 7);
});
