// Canonical values for the derived components we sign. These have to match
// crates/signprint-wire/src/sig.rs byte for byte; testvectors/wire.json is the
// referee.

export class CanonicalError extends Error {}

/** `@authority`: lowercase host, port dropped when it's the scheme default. */
export function canonicalAuthority(authority: string, https: boolean): string {
  if (authority === "" || authority.includes("@") || /[\s\x00-\x1f\x7f]/.test(authority)) {
    throw new CanonicalError(`bad authority: ${authority}`);
  }
  const lower = authority.toLowerCase();
  let host: string;
  let port: string | undefined;

  if (lower.startsWith("[")) {
    const end = lower.indexOf("]");
    if (end < 0) throw new CanonicalError(`bad authority: ${authority}`);
    host = lower.slice(0, end + 1);
    const rest = lower.slice(end + 1);
    if (rest !== "") {
      if (!rest.startsWith(":")) throw new CanonicalError(`bad authority: ${authority}`);
      port = rest.slice(1);
    }
  } else {
    const i = lower.lastIndexOf(":");
    if (i >= 0) {
      host = lower.slice(0, i);
      port = lower.slice(i + 1);
    } else {
      host = lower;
    }
    if (host.includes(":")) throw new CanonicalError(`bad authority: ${authority}`);
  }

  if (host === "") throw new CanonicalError(`bad authority: ${authority}`);
  if (port === undefined) return host;
  if (!/^[0-9]+$/.test(port)) throw new CanonicalError(`bad authority: ${authority}`);
  return port === (https ? "443" : "80") ? host : `${host}:${port}`;
}

/** `@path`: exactly as sent, `/` when empty. */
export function canonicalPath(path: string): string {
  return path === "" ? "/" : path;
}

/** `@query`: `?` plus the raw query, or just `?`. */
export function canonicalQuery(rawQuery: string | null): string {
  return "?" + (rawQuery ?? "");
}

/**
 * All three from a URL object. `URL` already lowercases the host and drops
 * default ports, but we still run it through canonicalAuthority so there is one
 * code path.
 */
export function componentsFromUrl(url: URL): { authority: string; path: string; query: string } {
  const https = url.protocol === "https:";
  if (!https && url.protocol !== "http:") throw new CanonicalError(`unsupported scheme ${url.protocol}`);
  // url.search is "" both for no query and for a bare "?", which is fine here:
  // both canonicalise to "?".
  const query = url.search === "" ? null : url.search.slice(1);
  return {
    authority: canonicalAuthority(url.host, https),
    path: canonicalPath(url.pathname),
    query: canonicalQuery(query),
  };
}
