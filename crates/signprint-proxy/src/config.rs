//! `signprint.toml` and the keyring file.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use signprint_core::network::Cidr;
use signprint_core::verdict::Mode;
use signprint_wire::{b64, keys::KeyRing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ModeSetting {
    /// Verify and report, never block. Where every deployment should start.
    #[default]
    Observe,
    Enforce,
}

impl From<ModeSetting> for Mode {
    fn from(m: ModeSetting) -> Self {
        match m {
            ModeSetting::Observe => Mode::Observe,
            ModeSetting::Enforce => Mode::Enforce,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Require {
    /// Every request needs a valid signprint/1 signature.
    Signed,
    /// Pass through untouched (apart from the verdict header).
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub path_prefix: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub require: Require,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// e.g. "0.0.0.0:443"
    pub tls: Option<String>,
    /// Plain HTTP listener. Only for local testing; no JA4 without TLS.
    pub plain: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// host:port of the app we protect
    pub addr: String,
    #[serde(default)]
    pub tls: bool,
    /// SNI to send when `tls` is on
    #[serde(default)]
    pub sni: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    pub keyring: PathBuf,
    /// Env var holding the base64url secret shared with the upstream app.
    pub upstream_secret_env: String,
    /// Env var holding the base64url root for day-keyed log hashes.
    pub log_root_env: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Hops allowed to forward a JA4 header. Empty means we compute JA4 ourselves.
    #[serde(default)]
    pub trusted_upstreams: Vec<String>,
    #[serde(default = "default_ja4_header")]
    pub ja4_header: String,
}

// The field defaults only apply when [network] is present at all; without
// this, a missing section would get an empty header name.
impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            trusted_upstreams: Vec::new(),
            ja4_header: default_ja4_header(),
        }
    }
}

fn default_ja4_header() -> String {
    "x-signprint-ja4".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    #[serde(default = "default_skew")]
    pub skew_secs: u64,
    #[serde(default = "default_max_requests")]
    pub max_requests: u64,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            skew_secs: default_skew(),
            max_requests: default_max_requests(),
            max_body_bytes: default_max_body(),
        }
    }
}

fn default_skew() -> u64 {
    30
}
fn default_max_requests() -> u64 {
    1000
}
fn default_max_body() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: ModeSetting,
    pub listen: Listen,
    pub tls: Option<Tls>,
    pub upstream: Upstream,
    pub keys: Keys,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub session: Session,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("parsing {0}: {1}")]
    Parse(PathBuf, String),
    #[error("{0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.into(), e))?;
        let cfg: Config =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(path.into(), e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        if self.listen.tls.is_none() && self.listen.plain.is_none() {
            return bad("listen: need at least one of `tls` or `plain`".into());
        }
        if self.listen.tls.is_some() && self.tls.is_none() {
            return bad("listen.tls is set but there's no [tls] section".into());
        }
        if self.session.max_body_bytes > 64 * 1024 {
            // pingora's retry buffer, which we rely on to replay the body, caps at 64 KiB
            return bad("session.max_body_bytes can't exceed 65536".into());
        }
        for r in &self.routes {
            if !r.path_prefix.starts_with('/') {
                return bad(format!(
                    "route path_prefix {:?} must start with /",
                    r.path_prefix
                ));
            }
        }
        for c in &self.network.trusted_upstreams {
            c.parse::<Cidr>().map_err(ConfigError::Invalid)?;
        }
        Ok(())
    }

    pub fn trusted_upstreams(&self) -> Vec<Cidr> {
        self.network
            .trusted_upstreams
            .iter()
            .map(|c| c.parse().expect("checked in validate"))
            .collect()
    }
}

/// On-disk keyring:
///
/// ```json
/// { "host_id": 1, "current": 2, "keys": [ { "kid": 1, "secret": "<base64url, 32 bytes>" }, ... ] }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringFile {
    host_id: u16,
    current: u8,
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    kid: u8,
    secret: String,
}

pub fn parse_keyring(json: &str) -> Result<KeyRing, ConfigError> {
    let f: KeyringFile =
        serde_json::from_str(json).map_err(|e| ConfigError::Invalid(format!("keyring: {e}")))?;
    let mut masters = Vec::with_capacity(f.keys.len());
    for k in &f.keys {
        masters.push((
            k.kid,
            secret32(&k.secret, &format!("keyring kid {}", k.kid))?,
        ));
    }
    KeyRing::new(f.host_id, f.current, &masters).ok_or_else(|| {
        ConfigError::Invalid(format!("keyring: current kid {} has no key", f.current))
    })
}

pub fn load_keyring(path: &Path) -> Result<KeyRing, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.into(), e))?;
    parse_keyring(&text)
}

pub fn secret32(encoded: &str, what: &str) -> Result<[u8; 32], ConfigError> {
    b64::decode_url(encoded.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ConfigError::Invalid(format!("{what}: expected 32 bytes of base64url")))
}

pub fn secret_from_env(var: &str) -> Result<[u8; 32], ConfigError> {
    let v =
        std::env::var(var).map_err(|_| ConfigError::Invalid(format!("env var {var} not set")))?;
    secret32(&v, var)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [listen]
        plain = "127.0.0.1:8080"

        [upstream]
        addr = "127.0.0.1:3000"

        [keys]
        keyring = "keyring.json"
        upstream_secret_env = "SIGNPRINT_UPSTREAM_SECRET"
        log_root_env = "SIGNPRINT_LOG_ROOT"

        [[route]]
        path_prefix = "/api/"
        methods = ["POST", "PUT"]
        require = "signed"
    "#;

    #[test]
    fn minimal_config_defaults() {
        let c: Config = toml::from_str(MINIMAL).unwrap();
        c.validate().unwrap();
        assert_eq!(c.mode, ModeSetting::Observe);
        assert_eq!(c.session.max_body_bytes, 65536);
        assert_eq!(c.routes[0].require, Require::Signed);
        assert_eq!(c.network.ja4_header, "x-signprint-ja4");
    }

    #[test]
    fn validation_errors() {
        let tls_without_cert = MINIMAL.replace("plain = ", "tls = ");
        let c: Config = toml::from_str(&tls_without_cert).unwrap();
        assert!(c.validate().is_err());

        let huge_body = format!("{MINIMAL}\n[session]\nmax_body_bytes = 1000000\n");
        let c: Config = toml::from_str(&huge_body).unwrap();
        assert!(c.validate().is_err());

        assert!(toml::from_str::<Config>(&format!("{MINIMAL}\nunknown_key = 1\n")).is_err());
    }

    #[test]
    fn keyring_parsing() {
        let k = b64::encode_url(&[7u8; 32]);
        let ring = parse_keyring(&format!(
            r#"{{"host_id": 3, "current": 2, "keys": [{{"kid": 1, "secret": "{k}"}}, {{"kid": 2, "secret": "{k}"}}]}}"#
        ))
        .unwrap();
        assert_eq!(ring.host_id(), 3);
        assert_eq!(ring.current_kid(), 2);

        assert!(parse_keyring(r#"{"host_id": 1, "current": 9, "keys": []}"#).is_err());
        assert!(
            parse_keyring(
                r#"{"host_id": 1, "current": 1, "keys": [{"kid": 1, "secret": "short"}]}"#
            )
            .is_err()
        );
    }
}
