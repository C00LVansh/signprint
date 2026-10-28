//! The two HTML pages and the fake catalogue.

use serde_json::{Value, json};

const ADJECTIVES: [&str; 12] = [
    "Quiet", "Brass", "Folding", "Cedar", "Pocket", "Woven", "Glazed", "Copper", "Linen", "Slate",
    "Amber", "Tidal",
];
const NOUNS: [&str; 12] = [
    "Lamp", "Kettle", "Notebook", "Stool", "Radio", "Basket", "Mug", "Clock", "Scarf", "Planter",
    "Tray", "Compass",
];

/// Deterministic fake product, so every scraper sees the same catalogue.
pub fn product(id: u32) -> Value {
    let h = id.wrapping_mul(2_654_435_761);
    json!({
        "id": id,
        "name": format!("{} {}", ADJECTIVES[(h % 12) as usize], NOUNS[((h >> 8) % 12) as usize]),
        "price_cents": 500 + (h >> 4) % 9500,
        "stock": (h >> 12) % 40,
    })
}

pub const INDEX: &str = r##"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>signprint demo</title>
<style>
  :root { color-scheme: light dark; --fg:#1b1d21; --muted:#5c6370; --bg:#fafaf9; --card:#fff; --line:#e4e4e7; --accent:#2f6fde; --bad:#c2410c; --ok:#15803d; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e7e7ea; --muted:#9aa0aa; --bg:#121316; --card:#1a1c20; --line:#2a2d33; --accent:#6ea0ff; --bad:#fb923c; --ok:#4ade80; } }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; color: var(--fg); background: var(--bg); }
  main { max-width: 920px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  p.lead { color: var(--muted); margin: 0 0 24px; max-width: 70ch; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
  @media (min-width: 760px) { .grid { grid-template-columns: 2fr 1fr; } }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
  .card h2 { font-size: 15px; margin: 0 0 12px; }
  table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
  td, th { text-align: left; padding: 6px 4px; border-bottom: 1px solid var(--line); }
  th { color: var(--muted); font-weight: 500; font-size: 13px; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  button, input { font: inherit; padding: 6px 10px; border-radius: 6px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); }
  button { cursor: pointer; } button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  input { width: 100%; margin-bottom: 8px; }
  .status { font-size: 13px; color: var(--muted); min-height: 1.5em; }
  .band { display: inline-block; padding: 1px 8px; border-radius: 99px; border: 1px solid var(--line); font-size: 13px; }
  .bad { color: var(--bad); } .ok { color: var(--ok); }
  a { color: var(--accent); }
  code { font-size: 13px; }
</style>
<main>
  <h1>Try to scrape this</h1>
  <p class="lead">
    Everything under <code>/api/</code> sits behind <a href="https://github.com/C00LVansh/signprint">signprint</a>.
    A browser gets a short-lived session by answering a fresh challenge, then signs every request with a key
    page scripts can't read. Get all 1000 products out from a session the proxy rates as clean (band 0 or 1),
    without a real browser doing the work. The <a href="/scoreboard">scoreboard</a> shows how everyone's doing.
  </p>
  <div class="grid">
    <section class="card">
      <h2>Catalogue</h2>
      <div class="row" style="margin-bottom:8px">
        <button id="prev">Previous</button>
        <span id="pageinfo">page –</span>
        <button id="next">Next</button>
        <span class="status" id="session"></span>
      </div>
      <table>
        <thead><tr><th>#</th><th>Product</th><th>Price</th><th>Stock</th></tr></thead>
        <tbody id="items"><tr><td colspan="4" class="status">Loading…</td></tr></tbody>
      </table>
    </section>
    <section class="card">
      <h2>Sign in</h2>
      <form id="login">
        <input name="user" placeholder="username (demo)" autocomplete="username">
        <input name="pass" type="password" placeholder="password (demo)" autocomplete="current-password">
        <button class="primary" type="submit">Sign in</button>
      </form>
      <p class="status" id="loginstatus"></p>
      <h2 style="margin-top:20px">Your session</h2>
      <p class="status" id="you">No session yet. One is created on your first request.</p>
    </section>
  </div>
</main>
<script type="module">
  import { SignprintClient } from "/static/signprint.js";

  const $ = (id) => document.getElementById(id);
  const status = $("session");
  const sp = new SignprintClient({
    onPowProgress: (n, expected) => { status.textContent = `proof of work ${Math.min(n, expected)}/~${expected}`; },
  });
  let page = 1, pages = 50;

  function showYou(you) {
    if (!you) return;
    const cls = you.band >= 2 ? "bad" : "ok";
    $("you").innerHTML = `Band <span class="band ${cls}">${you.band}</span>` +
      (you.pow ? " · earned with a proof of work" : "") +
      (you.band >= 2 ? "<br>This session looks automated to the proxy." : "");
  }

  async function load(p) {
    status.textContent = "getting a session…";
    try {
      const res = await sp.fetch(`/api/products?page=${p}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || res.status);
      page = body.page; pages = body.pages;
      $("pageinfo").textContent = `page ${page} / ${pages}`;
      $("items").innerHTML = body.items.map((it) =>
        `<tr><td>${it.id}</td><td>${it.name}</td><td>$${(it.price_cents / 100).toFixed(2)}</td><td>${it.stock}</td></tr>`).join("");
      status.textContent = "";
      showYou(body.you);
    } catch (e) {
      status.textContent = `failed: ${e.message}`;
    }
  }

  $("prev").onclick = () => page > 1 && load(page - 1);
  $("next").onclick = () => page < pages && load(page + 1);
  $("login").onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    $("loginstatus").textContent = "…";
    const res = await sp.fetch("/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: f.get("user"), pass: f.get("pass") }),
    });
    const body = await res.json();
    $("loginstatus").innerHTML = res.ok ? `<span class="ok">Signed in.</span>` : `<span class="bad">${body.error}</span>`;
  };
  load(1);
</script>
</html>
"##;

pub const SCOREBOARD: &str = r##"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>signprint scoreboard</title>
<style>
  :root { color-scheme: light dark; --fg:#1b1d21; --muted:#5c6370; --bg:#fafaf9; --card:#fff; --line:#e4e4e7; --bad:#c2410c; --ok:#15803d; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e7e7ea; --muted:#9aa0aa; --bg:#121316; --card:#1a1c20; --line:#2a2d33; --bad:#fb923c; --ok:#4ade80; } }
  body { margin: 0; font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; color: var(--fg); background: var(--bg); }
  main { max-width: 920px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-size: 24px; margin: 0 0 4px; } p { color: var(--muted); margin: 0 0 20px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
  .stat b { display: block; font-size: 22px; font-variant-numeric: tabular-nums; }
  .stat span { color: var(--muted); font-size: 13px; }
  .wrap { overflow-x: auto; background: var(--card); border: 1px solid var(--line); border-radius: 10px; }
  table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; min-width: 560px; }
  td, th { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); }
  th { color: var(--muted); font-weight: 500; font-size: 13px; }
  .bad { color: var(--bad); } .ok { color: var(--ok); } a { color: inherit; }
</style>
<main>
  <h1>Scoreboard</h1>
  <p>Sessions by how much of the 50-page catalogue they fetched. A session counts as a win if it got every page at band 0 or 1. Session ids are daily hashes; nothing here identifies anyone. <a href="/">Back to the demo</a></p>
  <div class="stats" id="stats"></div>
  <div class="wrap"><table>
    <thead><tr><th>Session</th><th>Band</th><th>Proof of work</th><th>Pages</th><th>Requests</th><th>Logins ok / held</th><th>Last seen</th></tr></thead>
    <tbody id="rows"></tbody>
  </table></div>
</main>
<script>
  const ago = (t) => { const s = Math.max(0, Math.round(Date.now() / 1000 - t)); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`; };
  async function refresh() {
    const d = await (await fetch("/scoreboard.json", { cache: "no-store" })).json();
    const t = d.totals;
    document.getElementById("stats").innerHTML = [
      ["Sessions", t.sessions], ["Signed requests", t.requests], ["Products served", t.products_served],
      ["…to sessions in band 2–3", t.products_to_high_bands], ["Refused, no verdict", t.rejected_without_verdict],
    ].map(([k, v]) => `<div class="stat"><b>${v}</b><span>${k}</span></div>`).join("");
    document.getElementById("rows").innerHTML = d.sessions.map((s) => {
      const win = s.band <= 1 && s.pages >= d.catalogue_pages;
      return `<tr><td><code>${s.session}</code>${win ? " 🏆" : ""}</td><td class="${s.band >= 2 ? "bad" : "ok"}">${s.band}</td>` +
        `<td>${s.pow ? "yes" : "–"}</td><td>${s.pages} / ${d.catalogue_pages}</td><td>${s.requests}</td>` +
        `<td>${s.logins_ok} / ${s.logins_blocked}</td><td>${ago(s.last_seen)}</td></tr>`;
    }).join("") || `<tr><td colspan="7">Nobody yet.</td></tr>`;
  }
  refresh(); setInterval(refresh, 5000);
</script>
</html>
"##;

#[cfg(test)]
mod tests {
    #[test]
    fn products_are_deterministic() {
        assert_eq!(super::product(7), super::product(7));
        assert_ne!(super::product(7)["name"], super::product(8)["name"]);
    }
}
