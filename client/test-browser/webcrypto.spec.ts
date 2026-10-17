// Checks the WebCrypto behaviour the session design depends on, in real
// browser engines rather than Node:
//   - deriveKey(ECDH -> HMAC) gives the same MAC key the server derives
//   - the derived key really is non-extractable
//   - non-extractable keys survive a round trip through IndexedDB
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/blank.html");
});

test("session key matches the server and can't be exported", async ({ page }) => {
  const results = await page.evaluate(async () => {
    const lib = "/dist/index.js";
    const { deriveSessionKey, mac } = await import(lib);
    const vectors = await (await fetch("/testvectors/wire.json")).json();
    const fromB64Url = (s: string) =>
      Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

    const out = [];
    for (const v of vectors.ecdh) {
      const priv = await crypto.subtle.importKey("jwk", v.client_jwk, { name: "ECDH", namedCurve: "P-256" }, false, [
        "deriveKey",
      ]);
      const key = await deriveSessionKey(priv, fromB64Url(v.server_public_raw));
      let exported = true;
      try {
        await crypto.subtle.exportKey("raw", key);
      } catch {
        exported = false;
      }
      out.push({ match: toB64(await mac(key, v.base)) === v.mac_b64, extractable: key.extractable, exported });
    }
    return out;
  });

  expect(results.length).toBeGreaterThan(0);
  for (const r of results) {
    expect(r).toEqual({ match: true, extractable: false, exported: false });
  }
});

test("keys survive IndexedDB when stored as separate records", async ({ page }) => {
  const stored = await page.evaluate(async () => {
    const lib = "/dist/index.js";
    const { deriveSessionKey, exportPublicKey, generateClientKey, mac } = await import(lib);
    const vectors = await (await fetch("/testvectors/wire.json")).json();
    const serverPub = Uint8Array.from(
      atob(vectors.ecdh[0].server_public_raw.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );

    const pair = await generateClientKey();
    const session = await deriveSessionKey(pair.privateKey, serverPub);
    const before = await mac(session, "hello");

    const open = () =>
      new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open("signprint-test", 1);
        req.onupgradeneeded = () => req.result.createObjectStore("keys");
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    const tx = <T>(db: IDBDatabase, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>) =>
      new Promise<T>((resolve, reject) => {
        const req = fn(db.transaction("keys", mode).objectStore("keys"));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });

    let db: IDBDatabase;
    try {
      db = await open();
    } catch (e) {
      return { ok: false, stage: "open", error: String(e) };
    }
    try {
      await tx(db, "readwrite", (s) => s.put(pair.privateKey, "client-private"));
      await tx(db, "readwrite", (s) => s.put(pair.publicKey, "client-public"));
      await tx(db, "readwrite", (s) => s.put(session, "session"));
    } catch (e) {
      return { ok: false, stage: "put", error: String(e) };
    }
    db.close();

    // whether the whole CryptoKeyPair can be cloned is worth knowing, but we
    // don't rely on it
    let pairClonable = true;
    try {
      const db2 = await open();
      await tx(db2, "readwrite", (s) => s.put(pair, "pair"));
      db2.close();
    } catch {
      pairClonable = false;
    }

    const db3 = await open();
    const priv = await tx<CryptoKey>(db3, "readonly", (s) => s.get("client-private"));
    const pub = await tx<CryptoKey>(db3, "readonly", (s) => s.get("client-public"));
    const restored = await tx<CryptoKey>(db3, "readonly", (s) => s.get("session"));
    db3.close();

    const after = await mac(restored, "hello");
    const rederived = await mac(await deriveSessionKey(priv, serverPub), "hello");
    const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
    return {
      ok: true,
      sessionSurvived: same(before, after),
      privateSurvived: same(before, rederived),
      privateStillLocked: priv.extractable === false && restored.extractable === false,
      publicExportable: (await exportPublicKey(pub)).length === 65,
      pairClonable,
    };
  });

  test.info().annotations.push({ type: "result", description: JSON.stringify(stored) });
  expect(stored).toMatchObject({
    ok: true,
    sessionSurvived: true,
    privateSurvived: true,
    privateStillLocked: true,
    publicExportable: true,
  });
});
