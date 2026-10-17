import { componentsFromUrl } from "./canonical.ts";
import { contentDigest, mac } from "./crypto.ts";
import type { Counter } from "./nonce.ts";
import { headerValues, signatureBase } from "./signature.ts";

export interface Session {
  /** Sealed session token from /attest; goes in keyid. */
  token: string;
  /** Non-extractable HMAC key from deriveSessionKey. */
  key: CryptoKey;
  counter: Counter;
  /** serverTime - Date.now() at attest, so a skewed local clock doesn't fail every request. */
  clockOffsetMs?: number;
}

export interface SignedHeaders {
  "signature-input": string;
  signature: string;
  "content-digest"?: string;
}

const BODYLESS = new Set(["GET", "HEAD"]);

/**
 * Signature headers for one request. `body` must be the exact bytes that will
 * be sent; an empty body counts as no body.
 */
export async function signRequest(
  method: string,
  url: string | URL,
  body: Uint8Array | null,
  session: Session,
  now: number = Date.now(),
): Promise<SignedHeaders> {
  const m = method.toUpperCase();
  const hasBody = body !== null && body.length > 0;
  if (hasBody && BODYLESS.has(m)) throw new TypeError(`${m} requests can't carry a body`);

  const { authority, path, query } = componentsFromUrl(typeof url === "string" ? new URL(url) : url);
  const digest = hasBody ? await contentDigest(body) : undefined;
  const params = {
    created: Math.floor((now + (session.clockOffsetMs ?? 0)) / 1000),
    keyid: session.token,
    nonce: session.counter.take(),
  };

  const base = signatureBase({ method: m, authority, path, query, contentDigest: digest }, params);
  const { signatureInput, signature } = headerValues(params, hasBody, await mac(session.key, base));

  const headers: SignedHeaders = { "signature-input": signatureInput, signature };
  if (digest !== undefined) headers["content-digest"] = digest;
  return headers;
}
