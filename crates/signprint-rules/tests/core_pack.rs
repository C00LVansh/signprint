//! Loads the shipped core pack and checks it against a few typical profiles.

use signprint_rules::{Pack, RuleSet, Signals, Value};

const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0";

fn core() -> RuleSet {
    let src = include_str!("../../../rulepacks/core/core.toml");
    RuleSet::new(vec![Pack::parse(src).expect("core pack parses")])
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

fn desktop_chrome() -> Signals {
    [
        ("js.engine", s("blink")),
        ("js.ua", s(CHROME_UA)),
        ("http.ua", s(CHROME_UA)),
        (
            "http.sec_ch_ua",
            s(r#""Chromium";v="141", "Google Chrome";v="141""#),
        ),
        ("js.webdriver", Value::Bool(false)),
        ("js.webdriver_type", s("boolean")),
        ("js.uad_brands", s("Chromium/141, Google Chrome/141")),
        ("js.uad_mobile", Value::Bool(false)),
        ("js.platform", s("Win32")),
        ("js.languages_len", Value::Num(2.0)),
        ("js.hw_concurrency", Value::Num(12.0)),
        ("js.plugins_len", Value::Num(5.0)),
        ("js.chrome_present", Value::Bool(true)),
        ("js.outer_w", Value::Num(1920.0)),
        ("js.outer_h", Value::Num(1040.0)),
        ("js.has_focus", Value::Bool(true)),
        (
            "js.webgl_renderer",
            s("ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ),
        ("js.lies", Value::Num(0.0)),
        ("js.notification_permission", s("default")),
        ("js.perm_notifications", s("prompt")),
        ("worker.ua", s(CHROME_UA)),
        ("worker.platform", s("Win32")),
        ("worker.hw_concurrency", Value::Num(12.0)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

#[test]
fn core_pack_loads_and_ids_are_unique() {
    let set = core();
    let pack = &set.packs()[0];
    assert_eq!(pack.meta.name, "core");
    assert!(pack.rules.len() >= 15);
}

#[test]
fn real_desktop_chrome_scores_zero() {
    let score = core().score(&desktop_chrome());
    assert_eq!(score.total(), 0, "unexpected hits: {:?}", score.hits);
}

#[test]
fn real_firefox_scores_zero() {
    let mut sig = desktop_chrome();
    for (k, v) in [
        ("js.engine", s("gecko")),
        ("js.ua", s(FIREFOX_UA)),
        ("http.ua", s(FIREFOX_UA)),
        ("worker.ua", s(FIREFOX_UA)),
        ("js.chrome_present", Value::Bool(false)),
    ] {
        sig.insert(k.into(), v);
    }
    // Firefox has no client hints or userAgentData
    sig.remove("http.sec_ch_ua");
    sig.remove("js.uad_brands");
    sig.remove("js.uad_mobile");
    let score = core().score(&sig);
    assert_eq!(score.total(), 0, "unexpected hits: {:?}", score.hits);
}

#[test]
fn default_headless_chrome_scores_high() {
    let mut sig = desktop_chrome();
    let ua = CHROME_UA.replace("Chrome/", "HeadlessChrome/");
    sig.insert("js.ua".into(), s(&ua));
    sig.insert("http.ua".into(), s(&ua));
    sig.insert("worker.ua".into(), s(&ua));
    sig.insert("js.webdriver".into(), Value::Bool(true));
    sig.insert(
        "js.webgl_renderer".into(),
        s("ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"),
    );
    let score = core().score(&sig);
    assert!(
        score.total() > 70,
        "headless only scored {}: {:?}",
        score.total(),
        score.hits
    );
}

#[test]
fn spoofed_ua_in_page_only_is_caught() {
    // what a JS-injection stealth plugin tends to do: patch navigator in the
    // page but not in workers or the HTTP header
    let mut sig = desktop_chrome();
    sig.insert("js.ua".into(), s(FIREFOX_UA));
    sig.insert("js.lies".into(), Value::Num(2.0));
    let score = core().score(&sig);
    let ids: Vec<&str> = score.hits.iter().map(|h| h.rule.as_str()).collect();
    assert!(ids.contains(&"core.ua_header_mismatch"));
    assert!(ids.contains(&"core.worker_ua_mismatch"));
    assert!(ids.contains(&"core.patched_natives"));
    assert!(score.total() > 70);
}

#[test]
fn missing_signals_dont_score() {
    assert_eq!(core().score(&Signals::new()).total(), 0);
}

fn hits(sig: &Signals) -> Vec<String> {
    core().score(sig).hits.into_iter().map(|h| h.rule).collect()
}

#[test]
fn canvas_rules() {
    let mut sig = desktop_chrome();
    sig.insert("cnv.present".into(), Value::Bool(true));
    sig.insert("cnv.noise".into(), s("exact"));

    let mut m = sig.clone();
    m.insert("cnv.match".into(), Value::Bool(true));
    assert_eq!(hits(&m), ["core.canvas_match"]);

    let mut unknown = sig.clone();
    unknown.insert("cnv.match".into(), Value::Bool(false));
    assert_eq!(hits(&unknown), ["core.canvas_unknown_answer"]);

    let mut lie = unknown.clone();
    lie.insert("cnv.class_lie".into(), Value::Bool(true));
    assert_eq!(hits(&lie), ["core.canvas_class_lie"]);

    let mut noisy = sig.clone();
    noisy.insert("cnv.noise".into(), s("noise"));
    assert_eq!(hits(&noisy), ["core.canvas_noise_unexplained"]);
    noisy.insert("js.uad_brands".into(), s("Brave/141, Chromium/141"));
    assert!(hits(&noisy).is_empty(), "Brave adds noise on purpose");

    let mut replayed = sig.clone();
    replayed.insert("cnv.shared_platforms".into(), Value::Num(3.0));
    assert_eq!(hits(&replayed), ["core.canvas_shared_answer"]);
    replayed.insert("cnv.shared_platforms".into(), Value::Num(2.0));
    assert!(hits(&replayed).is_empty());

    let mut gl_lie = sig.clone();
    gl_lie.insert("cnv.gl_match".into(), Value::Bool(false));
    gl_lie.insert("cnv.gl_class_lie".into(), Value::Bool(true));
    assert_eq!(hits(&gl_lie), ["core.webgl_gpu_lie"]);

    let mut gl_ok = sig.clone();
    gl_ok.insert("cnv.gl_match".into(), Value::Bool(true));
    assert_eq!(hits(&gl_ok), ["core.webgl_match"]);

    let mut skipped = desktop_chrome();
    skipped.insert("cnv.present".into(), Value::Bool(false));
    assert_eq!(hits(&skipped), ["core.canvas_skipped"]);
}
