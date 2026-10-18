// Sanity checks for the signal collector in real engines. These browsers are
// driven by Playwright, so they *are* automation: webdriver is expected to be
// true here. What we check is that the collector reads things correctly and
// doesn't mistake an unmodified browser for a tampered one.
import { expect, test } from "@playwright/test";

const ALL = [
  "js.engine",
  "js.ua",
  "js.platform",
  "js.webdriver",
  "js.webdriver_type",
  "js.languages_len",
  "js.hw_concurrency",
  "js.lies",
  "js.webgl_renderer",
  "worker.ua",
  "worker.platform",
  "worker.hw_concurrency",
  "not.a.signal",
];

test("collector reads a consistent, unpatched browser", async ({ page, browserName }) => {
  await page.goto("/blank.html");
  const s = await page.evaluate(async (wanted) => {
    const lib = "/dist/index.js";
    const { collectSignals } = await import(lib);
    return collectSignals(wanted);
  }, ALL);

  const engine = { chromium: "blink", firefox: "gecko", webkit: "webkit" }[browserName];
  expect(s["js.engine"]).toBe(engine);
  expect(s["js.lies"]).toBe(0);
  expect(s["js.webdriver_type"]).toBe("boolean");
  expect(s["worker.ua"]).toBe(s["js.ua"]);
  expect(s["worker.platform"]).toBe(s["js.platform"]);
  expect(s["worker.hw_concurrency"]).toBe(s["js.hw_concurrency"]);
  expect(s).not.toHaveProperty("not.a.signal");
  test.info().annotations.push({ type: "signals", description: JSON.stringify(s) });
});

test("a page-level navigator patch shows up as a lie", async ({ page }) => {
  await page.goto("/blank.html");
  const s = await page.evaluate(async () => {
    // roughly what a JS-injection stealth plugin does
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(navigator, "userAgent", { get: () => "Mozilla/5.0 Totally Real", configurable: true });
    const lib = "/dist/index.js";
    const { collectSignals } = await import(lib);
    return collectSignals(["js.lies", "js.ua", "worker.ua", "js.webdriver"]);
  });
  expect(s["js.webdriver"]).toBe(false);
  expect(s["js.lies"]).toBeGreaterThan(0);
  expect(s["worker.ua"]).not.toBe(s["js.ua"]);
});
