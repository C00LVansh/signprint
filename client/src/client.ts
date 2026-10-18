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
import { signRequest, type Session } from "./sign.ts";

const WELL_KNOWN = "/.well-known/signprint/v1/";
const ATTEST_DOMAIN = "signprint/1 attest\n";

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
}

export class SignprintClient {
  private readonly origin: string;
  private session: Promise<Session> | null = null;

  constructor(opts: ClientOptions = {}) {
    this.origin = opts.origin ?? location.origin;
  }

  /** Runs the challenge now instead of on the first request. */
  ready(): Promise<Session> {
    this.session ??= this.attest().catch((e) => {
      this.session = null;
      throw e;
    });
    return this.session;
  }

  /** Drops the current session; the next request attests again. */
  reset(): void {
    this.session = null;
  }

  private async attest(): Promise<Session> {
    const res = await fetch(this.origin + WELL_KNOWN + "challenge", { cache: "no-store", credentials: "same-origin" });
    if (!res.ok) throw await readError(res);
    const offer = (await res.json()) as Offer;

    await loadProgram(this.origin + offer.program);
    const probe = globalThis.__signprint?.[offer.probe_key];
    if (!probe) throw new Error("signprint: challenge program didn't register");
    delete globalThis.__signprint![offer.probe_key];
    const answers = probe();

    const client = await generateClientKey();
    const key = await deriveSessionKey(client.privateKey, fromBase64Url(offer.ephemeral_public));
    const body = JSON.stringify({
      cid: offer.cid,
      client_public: toBase64Url(await exportPublicKey(client.publicKey)),
      probe: answers,
    });
    const enc = new TextEncoder();
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(ATTEST_DOMAIN + body)));

    const att = await fetch(this.origin + WELL_KNOWN + "attest", {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "signprint-attest": toBase64(mac) },
      body,
    });
    if (!att.ok) throw await readError(att);
    const issued = (await att.json()) as { token: string; expires_at: number; server_time: number };

    return {
      token: issued.token,
      key,
      counter: new Counter(),
      clockOffsetMs: issued.server_time * 1000 - Date.now(),
    };
  }

  /** `fetch`, but signed. Re-attests and retries once if the proxy asks for it. */
  async fetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    const body = await bodyBytes(init, input);
    const method = (init.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const url = new URL(input instanceof Request ? input.url : String(input), location.href);

    for (let attempt = 0; ; attempt++) {
      const session = await this.ready();
      const signed = await signRequest(method, url, body, session);
      const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
      for (const [k, v] of Object.entries(signed)) headers.set(k, v);

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
        if (RETRYABLE.has(err.code)) {
          this.reset();
          continue;
        }
      }
      return res;
    }
  }
}
