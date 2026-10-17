// The signprint/1 profile of RFC 9421. See crates/signprint-wire/src/sig.rs for
// the verifier side; both have to produce identical signature bases.

import { toBase64 } from "./b64.ts";

export const LABEL = "sp";
export const TAG = "signprint/1";

const BASE_COMPONENTS = ["@method", "@authority", "@path", "@query"] as const;
const BODY_COMPONENT = "content-digest";

export interface Components {
  method: string;
  authority: string;
  path: string;
  /** Starts with "?". */
  query: string;
  /** The Content-Digest value; set iff the request has a body. */
  contentDigest?: string | undefined;
}

export interface Params {
  created: number;
  keyid: string;
  nonce: string;
}

export function signatureParams(p: Params, coversBody: boolean): string {
  const names = coversBody ? [...BASE_COMPONENTS, BODY_COMPONENT] : [...BASE_COMPONENTS];
  const list = "(" + names.map((n) => `"${n}"`).join(" ") + ")";
  return `${list};created=${p.created};keyid="${p.keyid}";nonce="${p.nonce}";tag="${TAG}"`;
}

export function signatureBase(c: Components, p: Params): string {
  const lines = [
    `"@method": ${c.method}`,
    `"@authority": ${c.authority}`,
    `"@path": ${c.path}`,
    `"@query": ${c.query}`,
  ];
  if (c.contentDigest !== undefined) lines.push(`"${BODY_COMPONENT}": ${c.contentDigest}`);
  lines.push(`"@signature-params": ${signatureParams(p, c.contentDigest !== undefined)}`);
  return lines.join("\n");
}

export function headerValues(
  p: Params,
  coversBody: boolean,
  mac: Uint8Array,
): { signatureInput: string; signature: string } {
  return {
    signatureInput: `${LABEL}=${signatureParams(p, coversBody)}`,
    signature: `${LABEL}=:${toBase64(mac)}:`,
  };
}
