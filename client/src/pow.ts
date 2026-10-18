// Argon2id proof-of-work, the browser side of crates/signprint-core/src/pow.rs.
//
// For each puzzle index i, find a nonce n such that
//   Argon2id(password = id || i || n_be32, salt = id || "signprint/1 pow")
// starts with `bits` zero bits. testvectors/pow.json pins this to the Rust
// implementation.

import { argon2id } from "hash-wasm";

import { fromBase64Url } from "./b64.ts";

export interface PowOffer {
  ticket: string;
  id: string;
  memory_kib: number;
  iterations: number;
  puzzles: number;
  bits: number;
  expires_at: number;
}

const SALT_SUFFIX = new TextEncoder().encode("signprint/1 pow");

export function leadingZeroBits(h: Uint8Array): number {
  let n = 0;
  for (const b of h) {
    if (b === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(b) - 24;
  }
  return n;
}

export async function powHash(
  id: Uint8Array,
  index: number,
  nonce: number,
  memoryKib: number,
  iterations: number,
): Promise<Uint8Array> {
  const password = new Uint8Array(21);
  password.set(id, 0);
  password[16] = index;
  new DataView(password.buffer).setUint32(17, nonce >>> 0, false);
  const salt = new Uint8Array(16 + SALT_SUFFIX.length);
  salt.set(id, 0);
  salt.set(SALT_SUFFIX, 16);
  return argon2id({
    password,
    salt,
    parallelism: 1,
    iterations,
    memorySize: memoryKib,
    hashLength: 32,
    outputType: "binary",
  });
}

export interface SolveOptions {
  /** Called after each attempt with the number of attempts so far. */
  onProgress?: (attempts: number) => void;
  signal?: AbortSignal;
}

/** Finds one nonce per puzzle. Expected cost is puzzles × 2^bits hashes. */
export async function solvePow(offer: PowOffer, opts: SolveOptions = {}): Promise<number[]> {
  const id = fromBase64Url(offer.id);
  const nonces: number[] = [];
  let attempts = 0;
  for (let i = 0; i < offer.puzzles; i++) {
    for (let n = 0; ; n++) {
      if (opts.signal?.aborted) throw new DOMException("aborted", "AbortError");
      const h = await powHash(id, i, n, offer.memory_kib, offer.iterations);
      attempts++;
      opts.onProgress?.(attempts);
      if (leadingZeroBits(h) >= offer.bits) {
        nonces.push(n);
        break;
      }
      // let the page breathe between hashes
      if (attempts % 4 === 0) await new Promise((r) => setTimeout(r, 0));
    }
  }
  return nonces;
}
