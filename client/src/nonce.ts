// Request nonces are "<tab>.<ctr>": a random 32-bit id per tab (8 lowercase hex
// digits) and that tab's counter. The server keeps a replay window per tab.

export function randomTabId(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0]!;
}

export function formatNonce(tab: number, ctr: bigint | number): string {
  if (!Number.isInteger(tab) || tab < 0 || tab > 0xffffffff) throw new RangeError("tab out of range");
  const c = BigInt(ctr);
  if (c < 0n || c > 0xffffffffffffffffn) throw new RangeError("counter out of range");
  return `${tab.toString(16).padStart(8, "0")}.${c.toString()}`;
}

export class Counter {
  readonly tab: number;
  private next: bigint;

  constructor(tab: number = randomTabId(), start: bigint = 0n) {
    this.tab = tab;
    this.next = start;
  }

  take(): string {
    return formatNonce(this.tab, this.next++);
  }
}
