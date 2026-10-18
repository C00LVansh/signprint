// Keeps the session across page loads.
//
// The session (token + non-extractable CryptoKeys) goes in IndexedDB, keyed
// by proxy origin. CryptoKeys survive structured cloning without ever becoming
// extractable. If IndexedDB isn't available (some private modes), everything
// still works, it just re-attests on each page load.
//
// The tab id and request counter go in sessionStorage: they belong to this
// tab, and must survive a reload so we don't reuse counters the server has
// already seen.

const DB = "signprint";
const STORE = "sessions";

export interface StoredSession {
  token: string;
  key: CryptoKey;
  clientPrivate: CryptoKey;
  clientPublic: string;
  /** server clock, seconds */
  expiresAt: number;
  clockOffsetMs: number;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export async function loadSession(origin: string): Promise<StoredSession | null> {
  try {
    const s = (await tx("readonly", (st) => st.get(origin))) as StoredSession | undefined;
    if (!s) return null;
    const serverNow = (Date.now() + s.clockOffsetMs) / 1000;
    if (serverNow >= s.expiresAt) {
      await clearSession(origin);
      return null;
    }
    return s;
  } catch {
    return null;
  }
}

export async function saveSession(origin: string, s: StoredSession): Promise<void> {
  try {
    await tx("readwrite", (st) => st.put(s, origin));
  } catch {
    // no persistence available; the in-memory session still works
  }
}

export async function clearSession(origin: string): Promise<void> {
  try {
    await tx("readwrite", (st) => st.delete(origin));
  } catch {
    // nothing to clear
  }
}

const COUNTER_KEY = "signprint:counter";

/** This tab's id and next counter, surviving reloads. */
export function loadCounterState(): { tab: number; next: bigint } | null {
  try {
    const raw = sessionStorage.getItem(COUNTER_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as { tab: number; next: string };
    return { tab: v.tab, next: BigInt(v.next) };
  } catch {
    return null;
  }
}

export function saveCounterState(tab: number, next: bigint): void {
  try {
    sessionStorage.setItem(COUNTER_KEY, JSON.stringify({ tab, next: next.toString() }));
  } catch {
    // storage blocked; a reload will just look like a new tab
  }
}
