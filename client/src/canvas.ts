// The browser side of the canvas challenge.
//
//  - pattern(): a known-answer image (solid rectangles) whose exact pixels the
//    server can compute. A different hash means the browser is adding noise
//    to canvas readbacks (Brave, Firefox fingerprinting protection, Safari
//    private mode...). The server treats that as a privacy browser, not a lie,
//    unless nothing else about the browser fits.
//
//  - challenge(): a Picasso-style drawing (Bursztein et al., 2016) built from
//    a server-chosen seed. Text, curves, gradients and shadows come out
//    slightly differently across browser, OS and GPU stacks, and the server
//    compares the hash with answers from calibrated devices of the same class.
//
// The PRNG matches crates/signprint-canvas/src/prng.rs exactly
// (testvectors/canvas.json).

import { toBase64Url } from "./b64.ts";

function splitmix32(state: { v: number }): number {
  state.v = (state.v + 0x9e3779b9) >>> 0;
  let z = state.v;
  z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
  z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
  return (z ^ (z >>> 16)) >>> 0;
}

const rotl = (x: number, k: number) => ((x << k) | (x >>> (32 - k))) >>> 0;

export class Rng {
  private s: [number, number, number, number];

  constructor(seed: number) {
    const st = { v: seed >>> 0 };
    this.s = [splitmix32(st), splitmix32(st), splitmix32(st), splitmix32(st)];
  }

  next(): number {
    const s = this.s;
    const result = Math.imul(rotl(Math.imul(s[1], 5) >>> 0, 7), 9) >>> 0;
    const t = (s[1] << 9) >>> 0;
    s[2] = (s[2] ^ s[0]) >>> 0;
    s[3] = (s[3] ^ s[1]) >>> 0;
    s[1] = (s[1] ^ s[2]) >>> 0;
    s[0] = (s[0] ^ s[3]) >>> 0;
    s[2] = (s[2] ^ t) >>> 0;
    s[3] = rotl(s[3], 11);
    return result;
  }

  range(lo: number, hi: number): number {
    return lo + (this.next() % (hi - lo + 1));
  }
}

export const PATTERN_W = 64;
export const PATTERN_H = 16;

export interface PatternRect {
  x: number;
  y: number;
  w: number;
  h: number;
  rgb: [number, number, number];
}

export function patternLayout(seed: number): { bg: [number, number, number]; rects: PatternRect[] } {
  const r = new Rng((seed ^ 0x70617474) >>> 0);
  const color = (): [number, number, number] => [r.range(16, 239), r.range(16, 239), r.range(16, 239)];
  const bg = color();
  const rects: PatternRect[] = [];
  for (let i = 0; i < 4; i++) {
    const x = r.range(0, PATTERN_W - 8);
    const y = r.range(0, PATTERN_H - 4);
    const w = r.range(4, PATTERN_W - x);
    const h = r.range(2, PATTERN_H - y);
    rects.push({ x, y, w, h, rgb: color() });
  }
  return { bg, rects };
}

async function sha256Hex(data: BufferSource): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function context(w: number, h: number): CanvasRenderingContext2D {
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  // fixed on purpose: without it Chrome may switch a canvas between GPU and
  // CPU raster after a few readbacks, and the answer would change mid-run
  const ctx = c.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("signprint: 2d canvas unavailable");
  return ctx;
}

/** Hash of the known-answer pattern as this browser reads it back. */
export async function pattern(seed: number): Promise<string> {
  const { bg, rects } = patternLayout(seed);
  const ctx = context(PATTERN_W, PATTERN_H);
  ctx.fillStyle = `rgb(${bg.join(",")})`;
  ctx.fillRect(0, 0, PATTERN_W, PATTERN_H);
  for (const r of rects) {
    ctx.fillStyle = `rgb(${r.rgb.join(",")})`;
    ctx.fillRect(r.x, r.y, r.w, r.h);
  }
  return sha256Hex(ctx.getImageData(0, 0, PATTERN_W, PATTERN_H).data);
}

const FONTS = ["Arial", "Times New Roman", "Courier New", "Georgia", "Verdana", "sans-serif", "serif"];

function randomColor(r: Rng): string {
  return `rgba(${r.range(0, 255)},${r.range(0, 255)},${r.range(0, 255)},${(r.range(40, 100) / 100).toFixed(2)})`;
}

function drawRound(ctx: CanvasRenderingContext2D, r: Rng, size: number): void {
  const p = () => r.range(0, size);
  const grad = ctx.createLinearGradient(p(), p(), p(), p());
  grad.addColorStop(0, randomColor(r));
  grad.addColorStop(r.range(10, 90) / 100, randomColor(r));
  grad.addColorStop(1, randomColor(r));
  ctx.fillStyle = grad;
  ctx.strokeStyle = grad;
  ctx.shadowBlur = r.range(0, 40);
  ctx.shadowColor = randomColor(r);
  ctx.shadowOffsetX = r.range(0, 10) - 5;
  ctx.shadowOffsetY = r.range(0, 10) - 5;
  ctx.lineWidth = r.range(1, 12);

  ctx.beginPath();
  switch (r.range(0, 3)) {
    case 0:
      ctx.arc(p(), p(), r.range(10, size / 2), (r.range(0, 360) * Math.PI) / 180, (r.range(0, 360) * Math.PI) / 180);
      ctx.fill();
      break;
    case 1:
      ctx.moveTo(p(), p());
      ctx.bezierCurveTo(p(), p(), p(), p(), p(), p());
      ctx.stroke();
      break;
    case 2:
      ctx.moveTo(p(), p());
      ctx.quadraticCurveTo(p(), p(), p(), p());
      ctx.stroke();
      break;
    default: {
      ctx.font = `${r.range(14, 48)}px "${FONTS[r.range(0, FONTS.length - 1)]}"`;
      const text = String.fromCharCode(...Array.from({ length: r.range(4, 10) }, () => r.range(0x21, 0x7e)));
      ctx.fillText(text + " \u{1F600}", r.range(0, size / 2), r.range(20, size));
      break;
    }
  }
}

/**
 * Picasso-style challenge: `rounds` seeded primitives, each round's pixels
 * chained into the hash, so the answer can't be built without rendering
 * every step. Returns a 128-bit hex answer.
 */
export async function challenge(seed: number, rounds: number, size: number): Promise<string> {
  const ctx = context(size, size);
  const r = new Rng(seed);
  const enc = new TextEncoder();
  let acc = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`signprint/1 canvas ${seed}`)));
  for (let i = 0; i < rounds; i++) {
    drawRound(ctx, r, size);
    const px = new Uint8Array(await crypto.subtle.digest("SHA-256", ctx.getImageData(0, 0, size, size).data));
    const joined = new Uint8Array(64);
    joined.set(acc, 0);
    joined.set(px, 32);
    acc = new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
  }
  return toBase64Url(acc.slice(0, 16));
}
