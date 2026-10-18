// The browser's Argon2id (WASM) has to agree with the Rust verifier.
import { expect, test } from "@playwright/test";

test("argon2id puzzle hashes match the Rust vectors", async ({ page }) => {
  await page.goto("/blank.html");
  const out = await page.evaluate(async () => {
    const lib = "/dist/signprint.js";
    const { solvePow } = await import(lib);
    const v = await (await fetch("/testvectors/pow.json")).json();
    const t0 = performance.now();
    const nonces = await solvePow({ ticket: "x", id: v.id, expires_at: 0, ...v.params });
    return { nonces, expected: v.solution, ms: performance.now() - t0 };
  });
  expect(out.nonces).toEqual(out.expected);
});
