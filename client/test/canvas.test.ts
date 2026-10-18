import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Rng, patternLayout } from "../src/canvas.ts";

const v = JSON.parse(readFileSync(new URL("../../testvectors/canvas.json", import.meta.url), "utf8"));

test("prng matches the Rust generator", () => {
  for (const p of v.prng) {
    const r = new Rng(p.seed);
    assert.deepEqual(
      Array.from({ length: p.first.length }, () => r.next()),
      p.first,
      `seed ${p.seed}`,
    );
  }
});

test("pattern layout matches the Rust side", () => {
  for (const p of v.patterns) {
    const { bg, rects } = patternLayout(p.seed);
    assert.deepEqual(bg, p.background);
    assert.deepEqual(
      rects.map((r) => [r.x, r.y, r.w, r.h, r.rgb]),
      p.rects,
    );
  }
});
