// The part apps actually use: get a session from the proxy, then sign requests
// with it.
//
//   const sp = new SignprintClient();
//   const res = await sp.fetch("/api/cart", { method: "POST", body: JSON.stringify(item) });
//
// Attestation happens lazily on the first protected request (or when you call
// ready()), not on page load.

import { fromBase64Url, toBase64, toBase64Url } from "./b64.ts";
import { deriveSessionKey, exportPublicKey, generateClientKey } from "./crypto.ts";
import { Counter } from "./nonce.ts";
import { challenge as canvasChallenge, pattern as canvasPattern } from "./canvas.ts";
import { solvePow, type PowOffer } from "./pow.ts";
import { collectSignals } from "./signals.ts";
import { signRequest } from "./sign.ts";
import { clearSession, loadCounterState, loadSession, saveCounterState, saveSession, type StoredSession } from "./store.ts";

const WELL_KNOWN = "/.well-known/signprint/v1/";
const ATTEST_DOMAIN = "signprint/1 attest\n";

// Must match FINGERPRINT_KEYS in crates/signprint-core/src/issue.rs.
const FINGERPRINT_KEYS = [
  "js.engine",
  "js.ua",
  "js.platform",
  "js.hw_concurrency",
  "js.languages_len",
  "js.webgl_renderer",
];

/** Refresh this long (seconds) before the token expires. */
const REFRESH_MARGIN = 120;

// errors where getting a fresh session and retrying once can help
const RETRYABLE = new Set(["sp_required", "sp_auth", "sp_stale", "sp_reattest", "sp_rebind", "sp_expired"]);

export class SignprintError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number) {
    super(`signprint: ${code} (${status})`);
    this.code = code;
    this.status = status;
  }
}

interface Offer {
  cid: string;
  probe_key: string;
  ephemeral_public: string;
  program: string;
  /** Signal names the server's rules read. */
  signals?: string[];
  canvas?: { seed: number; rounds: number; size: number; pattern_seed: number } | null;
  expires_at: number;
  server_time: number;
}

type ProbeFn = () => Record<string, number>;

declare global {
  // eslint-disable-next-line no-var
  var __signprint: Record<string, ProbeFn> | undefined;
}

async function readError(res: Response): Promise<SignprintError> {
  let code = "sp_unknown";
  try {
    code = (await res.json()).error ?? code;
  } catch {
    // not json; keep the generic code
  }
  return new SignprintError(code, res.status);
}

/** Loads the per-challenge program as a classic script so it works under CSP. */
function loadProgram(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.async = true;
    // pages with a nonce-based CSP: reuse the nonce our own loader came with
    const nonce = (document.currentScript as HTMLScriptElement | null)?.nonce || document.querySelector("script[nonce]")?.getAttribute("nonce");
    if (nonce) s.nonce = nonce;
    s.onload = () => {
      s.remove();
      resolve();
    };
    s.onerror = () => {
      s.remove();
      reject(new Error("signprint: couldn't load challenge program"));
    };
    document.head.appendChild(s);
  });
}

async function bodyBytes(init?: RequestInit, input?: RequestInfo | URL): Promise<Uint8Array | null> {
  if (init?.body == null && !(input instanceof Request)) return null;
  // Let the platform serialise it (FormData boundaries, URLSearchParams
  // encoding, ...), then sign exactly those bytes.
  const req = new Request(input instanceof Request ? input : "http://x/", init);
  const buf = new Uint8Array(await req.arrayBuffer());
  return buf.length > 0 ? buf : null;
}

export interface ClientOptions {
  /** Origin of the signprint proxy; defaults to the page's own origin. */
  origin?: string;
  /**
   * Called while a proof-of-work step-up is being solved, with the attempts
   * so far and the expected total. Use it to show progress; the puzzle
   * usually takes a second or a few.
   */
  onPowProgress?: (attempts: number, expected: number) => void;
}

export class SignprintClient {
  private readonly origin: string;
  private readonly onPowProgress: ClientOptions["onPowProgress"];
  private current: Promise<StoredSession> | null = null;
  private readonly counter: Counter;

  constructor(opts: ClientOptions = {}) {
    this.origin = opts.origin ?? location.origin;
    this.onPowProgress = opts.onPowProgress;
    const saved = loadCounterState();
    this.counter = saved ? new Counter(saved.tab, saved.next) : new Counter();
  }

  /** Gets a session now (from storage, or by running the challenge) instead of on the first request. */
  ready(): Promise<StoredSession> {
    this.current ??= this.restoreOrAttest().catch((e) => {
      this.current = null;
      throw e;
    });
    return this.current;
  }

  /** Forgets the session; the next request runs a fresh challenge. */
  reset(): void {
    this.current = null;
    void clearSession(this.origin);
  }

  /**
   * Swaps the session for a new token and key. If the server won't refresh
   * it (fingerprint changed, too old, ...), falls back to a full challenge.
   */
  async refresh(): Promise<void> {
    const prev = await this.ready();
    const next = this.refreshFrom(prev).catch(() => this.attest());
    this.current = next;
    next.catch(() => {
      if (this.current === next) this.current = null;
    });
    await next;
  }

  private async restoreOrAttest(): Promise<StoredSession> {
    return (await loadSession(this.origin)) ?? this.attest();
  }

  private async attest(): Promise<StoredSession> {
    const res = await fetch(this.origin + WELL_KNOWN + "challenge", { cache: "no-store", credentials: "same-origin" });
    if (!res.ok) throw await readError(res);
    const offer = (await res.json()) as Offer;

    await loadProgram(this.origin + offer.program);
    const probe = globalThis.__signprint?.[offer.probe_key];
    if (!probe) throw new Error("signprint: challenge program didn't register");
    delete globalThis.__signprint![offer.probe_key];
    const answers = probe();
    const signals = await collectSignals(offer.signals ?? []);
    let canvas: { answer: string; pattern: string } | undefined;
    if (offer.canvas) {
      try {
        canvas = {
          answer: await canvasChallenge(offer.canvas.seed, offer.canvas.rounds, offer.canvas.size),
          pattern: await canvasPattern(offer.canvas.pattern_seed),
        };
      } catch {
        // canvas blocked or unavailable; the server sees it wasn't answered
      }
    }

    const client = await generateClientKey();
    const clientPublic = toBase64Url(await exportPublicKey(client.publicKey));
    const key = await deriveSessionKey(client.privateKey, fromBase64Url(offer.ephemeral_public));
    const body = JSON.stringify({ cid: offer.cid, client_public: clientPublic, probe: answers, signals, canvas });
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(ATTEST_DOMAIN + body)));

    const att = await fetch(this.origin + WELL_KNOWN + "attest", {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "signprint-attest": toBase64(mac) },
      body,
    });
    if (!att.ok) throw await readError(att);
    let issued = (await att.json()) as { token?: string; pow?: PowOffer; expires_at: number; server_time: number };

    if (issued.pow) {
      // high band: earn the session with a proof of work
      const offer = issued.pow;
      const expected = offer.puzzles * 2 ** offer.bits;
      const nonces = await solvePow(offer, { onProgress: (n) => this.onPowProgress?.(n, expected) });
      const red = await fetch(this.origin + WELL_KNOWN + "pow", {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ticket: offer.ticket, nonces }),
      });
      if (!red.ok) throw await readError(red);
      issued = await red.json();
    }
    if (!issued.token) throw new Error("signprint: attest response had no session");

    const session: StoredSession = {
      token: issued.token,
      key,
      clientPrivate: client.privateKey,
      clientPublic,
      expiresAt: issued.expires_at,
      clockOffsetMs: issued.server_time * 1000 - Date.now(),
    };
    await saveSession(this.origin, session);
    return session;
  }

  private async refreshFrom(s: StoredSession): Promise<StoredSession> {
    const body = new TextEncoder().encode(
      JSON.stringify({ client_public: s.clientPublic, fp: await collectSignals(FINGERPRINT_KEYS) }),
    );
    const url = new URL(this.origin + WELL_KNOWN + "refresh");
    const headers = await this.sign(s, "POST", url, body);
    headers.set("content-type", "application/json");
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: body as BodyInit,
      cache: "no-store",
      credentials: "same-origin",
      redirect: "manual",
    });
    if (!res.ok) throw await readError(res);
    const r = (await res.json()) as { token: string; ephemeral_public: string; expires_at: number; server_time: number };

    const fresh: StoredSession = {
      ...s,
      token: r.token,
      // same client key, new server key: only we can derive this
      key: await deriveSessionKey(s.clientPrivate, fromBase64Url(r.ephemeral_public)),
      expiresAt: r.expires_at,
      clockOffsetMs: r.server_time * 1000 - Date.now(),
    };
    await saveSession(this.origin, fresh);
    return fresh;
  }

  private async sign(s: StoredSession, method: string, url: URL, body: Uint8Array | null): Promise<Headers> {
    const signed = await signRequest(method, url, body, {
      token: s.token,
      key: s.key,
      counter: this.counter,
      clockOffsetMs: s.clockOffsetMs,
    });
    saveCounterState(this.counter.tab, this.counter.upcoming);
    const headers = new Headers();
    for (const [k, v] of Object.entries(signed)) headers.set(k, v);
    return headers;
  }

  /**
   * Operators only: renders every seed in the proxy's canvas pool on this
   * device and records the answers for the class this browser claims. Run it
   * on real devices you trust (your own machines, a device lab); the answers
   * become what other browsers of the same class are compared against.
   */
  async calibrate(token: string): Promise<{ class: string; added: number }> {
    const headers = { "signprint-calibrate": token };
    const list = await fetch(this.origin + WELL_KNOWN + "calibrate", { headers, cache: "no-store" });
    if (!list.ok) throw await readError(list);
    const { seeds, rounds, size } = (await list.json()) as { seeds: number[]; rounds: number; size: number };
    const answers: [number, string][] = [];
    for (const seed of seeds) answers.push([seed, await canvasChallenge(seed, rounds, size)]);
    const device = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("");
    const res = await fetch(this.origin + WELL_KNOWN + "calibrate", {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ device, answers }),
    });
    if (!res.ok) throw await readError(res);
    return res.json();
  }

  /** `fetch`, but signed. Refreshes or re-attests and retries once if the proxy asks for it. */
  async fetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    const body = await bodyBytes(init, input);
    const method = (init.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const url = new URL(input instanceof Request ? input.url : String(input), location.href);

    for (let attempt = 0; ; attempt++) {
      let s = await this.ready();
      if ((Date.now() + s.clockOffsetMs) / 1000 >= s.expiresAt - REFRESH_MARGIN) {
        await this.refresh();
        s = await this.ready();
      }

      const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
      for (const [k, v] of await this.sign(s, method, url, body)) headers.set(k, v);
      const res = await fetch(url, {
        ...init,
        method,
        headers,
        body: body as BodyInit | null,
        // a redirect would change @path/@authority and break the signature
        redirect: "manual",
      });

      if (attempt === 0 && (res.status === 401 || res.status === 400)) {
        const err = await readError(res.clone());
        if (err.code === "sp_rebind") {
          await this.refresh();
          continue;
        }
        if (RETRYABLE.has(err.code)) {
          // Another tab may have refreshed the shared session, which retires
          // the token we hold. Pick up the stored one before starting over.
          const stored = await loadSession(this.origin);
          if (stored && stored.token !== s.token) {
            this.current = Promise.resolve(stored);
            continue;
          }
          this.reset();
          continue;
        }
      }
      return res;
    }
  }
}
