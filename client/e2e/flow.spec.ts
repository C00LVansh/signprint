// Full stack: browser -> signprint proxy (TLS, JA4) -> echo upstream.
import { expect, test } from "@playwright/test";

type Echo = { headers: Record<string, string>; body_len: number; path: string };

test.beforeEach(async ({ page }) => {
  await page.goto("/e2e/index.html");
  await page.waitForFunction(() => (window as unknown as { clientLoaded?: boolean }).clientLoaded === true);
});

test("challenge, attest, then signed requests are allowed", async ({ page }) => {
  const steps: string[] = [];
  page.on("request", (r) => {
    const m = /\/\.well-known\/signprint\/v1\/(challenge|attest|pow)$/.exec(r.url());
    if (m) steps.push(m[1]!);
  });
  const out = await page.evaluate(async () => {
    const { SignprintClient } = window as unknown as {
      SignprintClient: new () => { fetch(i: string, init?: RequestInit): Promise<Response> };
    };
    const sp = new SignprintClient();
    const results = [];
    for (const qty of [1, 2, 3]) {
      const res = await sp.fetch(`/api/cart?n=${qty}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ qty }),
      });
      results.push({ status: res.status, echo: (await res.json()) as Echo });
    }
    const get = await sp.fetch("/api/items");
    results.push({ status: get.status, echo: (await get.json()) as Echo });
    return results;
  });

  for (const r of out) {
    expect(r.status).toBe(200);
    expect(r.echo.headers["signprint-verdict"]).toMatch(/^v=1;act=allow;mode=enforce;/);
  }
  // These browsers are Playwright-driven, so navigator.webdriver is true and
  // the core pack should put them in band 2 or 3. The app sees the band and
  // decides what to do with it.
  const band = Number(/;band=(\d);/.exec(out[0]!.echo.headers["signprint-verdict"]!)![1]);
  expect(band).toBeGreaterThanOrEqual(2);
  // ...and at band 2+ the session had to be earned with a proof of work
  expect(steps).toEqual(["challenge", "attest", "pow"]);
  const flags = Number(/;flags=(\d+);/.exec(out[0]!.echo.headers["signprint-verdict"]!)![1]);
  expect(flags & 2).toBe(2); // POW_PASSED
  expect(out[0]!.echo.body_len).toBe(JSON.stringify({ qty: 1 }).length);
  expect(out[0]!.echo.path).toBe("/api/cart?n=1");
  // same session for every request: the day-keyed sid hash doesn't change
  const sids = out.map((r) => /;sid=([0-9a-f]+);/.exec(r.echo.headers["signprint-verdict"]!)![1]);
  expect(new Set(sids).size).toBe(1);
});

test("unsigned API calls are refused", async ({ page }) => {
  const res = await page.evaluate(async () => {
    const r = await fetch("/api/cart", { method: "POST", body: "{}" });
    return { status: r.status, body: await r.json() };
  });
  expect(res.status).toBe(401);
  expect(res.body.error).toBe("sp_required");
});

test("a replayed signed request is refused", async ({ page }) => {
  const res = await page.evaluate(async () => {
    const { SignprintClient } = window as unknown as {
      SignprintClient: new () => { fetch(i: string, init?: RequestInit): Promise<Response> };
    };
    // capture the signed headers from one request and send them again verbatim
    let captured: Headers | null = null;
    const realFetch = window.fetch;
    window.fetch = async (input, init) => {
      if (String(input).includes("/api/once")) captured = new Headers(init?.headers);
      return realFetch(input, init);
    };
    const sp = new SignprintClient();
    const first = await sp.fetch("/api/once");
    window.fetch = realFetch;
    const replay = await fetch("/api/once", { headers: captured! });
    return { first: first.status, replay: replay.status, error: (await replay.json()).error };
  });
  expect(res.first).toBe(200);
  expect(res.replay).toBe(401);
  expect(res.error).toBe("sp_auth");
});

type Client = {
  fetch(i: string, init?: RequestInit): Promise<Response>;
  refresh(): Promise<void>;
};

async function signedCall(page: import("@playwright/test").Page, refreshFirst = false) {
  return page.evaluate(async (refreshFirst) => {
    const { SignprintClient } = window as unknown as { SignprintClient: new () => Client };
    const sp = new SignprintClient();
    if (refreshFirst) await sp.refresh();
    const res = await sp.fetch("/api/items");
    return { status: res.status, verdict: ((await res.json()) as Echo).headers["signprint-verdict"]! };
  }, refreshFirst);
}

const sidOf = (verdict: string) => /;sid=([0-9a-f]+);/.exec(verdict)![1];

test("the session survives a reload without a new challenge", async ({ page }) => {
  let challenges = 0;
  page.on("request", (r) => {
    if (r.url().endsWith("/.well-known/signprint/v1/challenge")) challenges++;
  });

  const first = await signedCall(page);
  await page.reload();
  await page.waitForFunction(() => (window as unknown as { clientLoaded?: boolean }).clientLoaded === true);
  const second = await signedCall(page);

  expect(first.status).toBe(200);
  expect(second.status).toBe(200);
  expect(second.verdict).toMatch(/;act=allow;/);
  expect(challenges).toBe(1);
  expect(sidOf(second.verdict)).toBe(sidOf(first.verdict));
});

test("refresh swaps the key and keeps the session", async ({ page }) => {
  let refreshes = 0;
  page.on("request", (r) => {
    if (r.url().endsWith("/.well-known/signprint/v1/refresh")) refreshes++;
  });
  const before = await signedCall(page);
  const after = await signedCall(page, true);
  expect(refreshes).toBe(1);
  expect(after.status).toBe(200);
  expect(after.verdict).toMatch(/;act=allow;/);
  expect(sidOf(after.verdict)).toBe(sidOf(before.verdict));
});

test("calibration, then the same engine's answers match", async ({ page }) => {
  const out = await page.evaluate(async () => {
    const { SignprintClient } = window as unknown as {
      SignprintClient: new () => Client & { calibrate(t: string): Promise<{ class: string; added: number }>; reset(): void };
    };
    const sp = new SignprintClient();
    let wrongToken = "";
    try {
      await sp.calibrate("not-the-token");
    } catch (e) {
      wrongToken = (e as { code?: string }).code ?? String(e);
    }
    const cal = await sp.calibrate("e2e-calibration-token");
    // a fresh session now runs the challenge against the calibrated class
    sp.reset();
    const res = await sp.fetch("/api/items");
    return { wrongToken, cal, status: res.status };
  });
  expect(out.wrongToken).toBe("sp_auth");
  expect(out.cal.added).toBeGreaterThan(0);
  expect(out.cal.class).toMatch(/^(blink|gecko|webkit)\/\d+\/\w+$/);
  expect(out.status).toBe(200);
});

test("another tab refreshing doesn't break this one", async ({ context }) => {
  const a = await context.newPage();
  const b = await context.newPage();
  for (const p of [a, b]) {
    await p.goto("/e2e/index.html");
    await p.waitForFunction(() => (window as unknown as { clientLoaded?: boolean }).clientLoaded === true);
  }
  let challenges = 0;
  context.on("request", (r) => {
    if (r.url().endsWith("/.well-known/signprint/v1/challenge")) challenges++;
  });
  const call = (p: import("@playwright/test").Page, refresh: boolean) =>
    p.evaluate(async (refresh) => {
      const w = window as unknown as { sp?: Client; SignprintClient: new () => Client };
      w.sp ??= new w.SignprintClient();
      if (refresh) await w.sp.refresh();
      return (await w.sp.fetch("/api/items")).status;
    }, refresh);

  expect(await call(a, false)).toBe(200); // a attests; the session is stored
  expect(await call(b, false)).toBe(200); // b picks it up from storage
  expect(await call(a, true)).toBe(200); // a refreshes: b's token is now retired
  expect(await call(b, false)).toBe(200); // b recovers from storage, no new challenge
  expect(challenges).toBe(1);
});
