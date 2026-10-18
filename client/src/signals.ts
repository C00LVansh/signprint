// Collects the browser signals the server's rule packs ask for. Only names in
// the challenge's `signals` list are sent; anything else stays on the page.
//
// Everything here is a generic, long-published check. It's cheap to collect
// and only interesting in combination: a real browser is consistent with
// itself, sloppy automation and spoofing usually aren't.

type SignalValue = string | number | boolean | null;
export type Signals = Record<string, SignalValue>;

/** Which engine actually runs this code, judged by error message wording. */
function engine(): string {
  try {
    // @ts-expect-error deliberate null dereference
    null.x;
  } catch (e) {
    const m = String((e as Error).message);
    if (m.startsWith("Cannot read prop")) return "blink";
    // newer SpiderMonkey: "can't access property ...", older: "... has no properties"
    if (m.startsWith("can't access property") || m.includes("has no properties")) return "gecko";
    if (m.includes("is not an object")) return "webkit";
  }
  return "unknown";
}

const NATIVE = /\{\s*\[native code\]\s*\}\s*$/;

/** Counts built-ins that don't look native any more (patched by a script). */
function lies(): number {
  const fnToString = Function.prototype.toString;
  const getter = (proto: object, name: string) => Object.getOwnPropertyDescriptor(proto, name)?.get;
  const targets: unknown[] = [
    getter(Navigator.prototype, "webdriver"),
    getter(Navigator.prototype, "userAgent"),
    getter(Navigator.prototype, "platform"),
    getter(Navigator.prototype, "languages"),
    getter(Navigator.prototype, "hardwareConcurrency"),
    getter(Navigator.prototype, "plugins"),
    HTMLCanvasElement.prototype.toDataURL,
    typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype.getParameter : undefined,
    fnToString,
  ];
  let count = 0;
  for (const t of targets) {
    if (typeof t !== "function") continue;
    let src = "";
    try {
      src = fnToString.call(t);
    } catch {
      count++;
      continue;
    }
    // native functions print as [native code] and have no own prototype
    if (!NATIVE.test(src) || Object.prototype.hasOwnProperty.call(t, "prototype")) count++;
  }
  // instance-level overrides on navigator itself are another common tell
  if (Object.getOwnPropertyNames(navigator).length > 0) count++;
  return count;
}

function webglRenderer(): string | null {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (!gl) return null;
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    return String(gl.getParameter(ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER));
  } catch {
    return null;
  }
}

async function permission(name: string): Promise<string | null> {
  try {
    return (await navigator.permissions.query({ name: name as PermissionName })).state;
  } catch {
    return null;
  }
}

const WORKER_SRC = `self.onmessage=function(){var n=self.navigator;postMessage({ua:n.userAgent,platform:n.platform,hw:n.hardwareConcurrency,langs:(n.languages||[]).length})}`;

/** What a Web Worker sees. Workers run in a separate realm that page-level
 *  patches usually don't reach. Null if workers are blocked (e.g. by CSP). */
function workerView(timeoutMs = 1000): Promise<Record<string, SignalValue> | null> {
  return new Promise((resolve) => {
    let url = "";
    let w: Worker | null = null;
    const done = (v: Record<string, SignalValue> | null) => {
      clearTimeout(timer);
      w?.terminate();
      if (url) URL.revokeObjectURL(url);
      resolve(v);
    };
    const timer = setTimeout(() => done(null), timeoutMs);
    try {
      url = URL.createObjectURL(new Blob([WORKER_SRC], { type: "text/javascript" }));
      w = new Worker(url);
      w.onmessage = (e) => done(e.data);
      w.onerror = () => done(null);
      w.postMessage(0);
    } catch {
      done(null);
    }
  });
}

/** Collects everything we know how to collect, then keeps the wanted names. */
export async function collectSignals(wanted: readonly string[]): Promise<Signals> {
  if (wanted.length === 0) return {};
  const want = new Set(wanted);
  const n = navigator as Navigator & {
    userAgentData?: { brands: { brand: string; version: string }[]; mobile: boolean };
  };
  const all: Signals = {
    "js.engine": engine(),
    "js.ua": n.userAgent,
    "js.platform": n.platform,
    "js.webdriver": typeof n.webdriver === "boolean" ? n.webdriver : null,
    "js.webdriver_type": typeof n.webdriver,
    "js.languages_len": n.languages?.length ?? null,
    "js.hw_concurrency": n.hardwareConcurrency ?? null,
    "js.plugins_len": n.plugins?.length ?? null,
    "js.chrome_present": "chrome" in window,
    "js.uad_brands": n.userAgentData ? n.userAgentData.brands.map((b) => `${b.brand}/${b.version}`).join(", ") : null,
    "js.uad_mobile": n.userAgentData ? n.userAgentData.mobile : null,
    "js.outer_w": window.outerWidth,
    "js.outer_h": window.outerHeight,
    "js.has_focus": document.hasFocus(),
    "js.notification_permission": typeof Notification !== "undefined" ? Notification.permission : null,
  };
  if (want.has("js.lies")) all["js.lies"] = lies();
  if (want.has("js.webgl_renderer")) all["js.webgl_renderer"] = webglRenderer();
  if (want.has("js.perm_notifications")) all["js.perm_notifications"] = await permission("notifications");

  if ([...want].some((k) => k.startsWith("worker."))) {
    const w = await workerView();
    if (w) {
      all["worker.ua"] = w.ua ?? null;
      all["worker.platform"] = w.platform ?? null;
      all["worker.hw_concurrency"] = w.hw ?? null;
      all["worker.languages_len"] = w.langs ?? null;
    }
  }

  const out: Signals = {};
  for (const k of want) if (k in all) out[k] = all[k]!;
  return out;
}
