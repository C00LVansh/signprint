// WebCrypto pieces: the content digest, the session MAC key and the MAC.
//
// The session key is derived with ECDH straight into a non-extractable HMAC
// key, so the raw secret never exists as bytes in JS. A script on the page can
// still ask us to sign things while the session is alive, but it can't copy
// the key somewhere else.

import { toBase64 } from "./b64.ts";

const subtle = globalThis.crypto.subtle;

export async function contentDigest(body: Uint8Array): Promise<string> {
  const hash = new Uint8Array(await subtle.digest("SHA-256", body as BufferSource));
  return `sha-256=:${toBase64(hash)}:`;
}

export async function generateClientKey(): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
}

export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

export async function deriveSessionKey(
  clientPrivate: CryptoKey,
  serverPublicRaw: Uint8Array,
): Promise<CryptoKey> {
  const serverPublic = await subtle.importKey(
    "raw",
    serverPublicRaw as BufferSource,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  return subtle.deriveKey(
    { name: "ECDH", public: serverPublic },
    clientPrivate,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
}

export async function mac(key: CryptoKey, base: string): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign("HMAC", key, new TextEncoder().encode(base)));
}
