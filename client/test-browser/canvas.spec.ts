// The canvas challenge in real engines.
import { expect, test } from "@playwright/test";

test("known-answer pattern and challenge stability", async ({ page }) => {
  await page.goto("/blank.html");
  const out = await page.evaluate(async () => {
    const lib = "/dist/signprint.js";
    const { canvasPattern, canvasChallenge } = await import(lib);
    const v = await (await fetch("/testvectors/canvas.json")).json();
    const patterns = [];
    for (const p of v.patterns) patterns.push({ got: await canvasPattern(p.seed), want: p.hash });
    const a1 = await canvasChallenge(12345, 3, 240);
    const a2 = await canvasChallenge(12345, 3, 240);
    const b = await canvasChallenge(54321, 3, 240);
    return { patterns, a1, a2, b };
  });
  test.info().annotations.push({ type: "canvas", description: JSON.stringify(out) });

  // the same seed renders the same way twice in one browser...
  expect(out.a1).toBe(out.a2);
  // ...and different seeds don't collide
  expect(out.a1).not.toBe(out.b);
  expect(out.a1).toMatch(/^[A-Za-z0-9_-]{22}$/);

  const exact = out.patterns.filter((p) => p.got === p.want).length;
  if (test.info().project.name === "firefox-private") {
    // private browsing turns on Firefox's canvas randomisation, which is
    // exactly what the known-answer pattern is there to notice
    test.info().annotations.push({ type: "pattern-exact", description: `${exact}/${out.patterns.length}` });
  } else {
    expect(exact).toBe(out.patterns.length);
  }
});

test("content-seeded noise is invisible to render-twice but caught by the pattern", async ({ page }) => {
  await page.goto("/blank.html");
  const out = await page.evaluate(async () => {
    // Roughly how Brave farbles: tweak the low bit of one channel on some
    // pixels, choosing them from a hash of the canvas contents. Same contents,
    // same noise.
    const orig = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args: Parameters<typeof orig>) {
      const img = orig.apply(this, args);
      let h = 2166136261;
      for (let i = 0; i < img.data.length; i += 97) h = Math.imul(h ^ img.data[i]!, 16777619) >>> 0;
      for (let i = 0; i < img.data.length; i += 4) {
        h = Math.imul(h ^ i, 16777619) >>> 0;
        if (((h >>> 13) & 7) === 0 && img.data[i]! > 0) img.data[i]! ^= 1;
      }
      return img;
    };
    const lib = "/dist/signprint.js";
    const { canvasPattern } = await import(lib);
    const v = await (await fetch("/testvectors/canvas.json")).json();
    const p = v.patterns[0];
    return { first: await canvasPattern(p.seed), second: await canvasPattern(p.seed), want: p.hash };
  });
  expect(out.first).toBe(out.second); // rendering twice sees nothing wrong
  expect(out.first).not.toBe(out.want); // the known answer does
});
