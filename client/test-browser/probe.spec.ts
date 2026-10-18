// Runs the server-generated probe programs from testvectors/probe.json in real
// engines and checks each one produces the answer the Rust side computed.
import { expect, test } from "@playwright/test";

test("probe programs agree with the server", async ({ page }) => {
  await page.goto("/blank.html");
  const results = await page.evaluate(async () => {
    const { programs } = await (await fetch("/testvectors/probe.json")).json();
    const out = [];
    for (const p of programs) {
      // load it the way the client will: as a classic script
      const blob = new Blob([p.source], { type: "text/javascript" });
      const url = URL.createObjectURL(blob);
      await new Promise<void>((resolve, reject) => {
        const s = document.createElement("script");
        s.src = url;
        s.onload = () => resolve();
        s.onerror = () => reject(new Error("script failed"));
        document.head.appendChild(s);
      });
      URL.revokeObjectURL(url);
      const registry = (self as unknown as { __signprint: Record<string, () => Record<string, number>> }).__signprint;
      const got = registry[p.registry_key]!();
      out.push({ expected: p.answer, got: got[p.field] });
    }
    return out;
  });

  expect(results.length).toBe(5);
  for (const r of results) expect(r.got).toBe(r.expected);
});
