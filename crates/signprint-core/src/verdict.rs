//! The `Signprint-Verdict` header the proxy adds before forwarding, and the
//! check the upstream app runs on it.
//!
//! ```text
//! v=1;act=allow;mode=enforce;band=0;flags=0;sid=3fa9c21e;rid=00000000075bcd15;ts=1760716801;rh=…;mac=…
//! ```
//!
//! The MAC covers everything before `;mac=`. `rh` is a hash of the request
//! line, so a verdict copied onto a different request doesn't check out.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use signprint_wire::b64;

pub const HEADER: &str = "signprint-verdict";
const DOMAIN: &[u8] = b"signprint-verdict/1\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Signed and verified.
    Allow,
    /// Failed verification. Only reaches the upstream in observe mode.
    Deny,
    /// Route isn't protected; nothing was checked.
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    pub mode: Mode,
    /// Failure code when `action` is `Deny`.
    pub reason: Option<String>,
    pub band: u8,
    pub flags: u8,
    /// Day-keyed hash of the session id; links requests from one session for
    /// a day and nothing more.
    pub sid: Option<[u8; 4]>,
    pub request_id: u64,
    pub ts: u64,
    pub request_hash: [u8; 12],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerdictError {
    #[error("verdict header missing")]
    Missing,
    #[error("verdict header malformed")]
    Malformed,
    #[error("verdict MAC doesn't verify")]
    BadMac,
    #[error("verdict is for a different request")]
    WrongRequest,
    #[error("verdict too old")]
    Stale,
}

/// Hash of the request line the verdict is about.
pub fn request_hash(method: &str, authority: &str, path: &str, query: Option<&str>) -> [u8; 12] {
    let mut h = Sha256::new();
    for part in [
        method,
        &authority.to_ascii_lowercase(),
        path,
        query.unwrap_or(""),
    ] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.finalize()[..12].try_into().expect("12 <= 32")
}

/// Per-day key for hashing session ids in verdicts and logs. Derived from a
/// root that's separate from the token keys.
pub fn day_key(log_root: &[u8; 32], day: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&day.to_be_bytes()), log_root);
    let mut out = [0u8; 32];
    hk.expand(b"signprint/1 log", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

pub fn sid_hash(day_key: &[u8; 32], sid: &[u8; 16]) -> [u8; 4] {
    let mut m = Hmac::<Sha256>::new_from_slice(day_key).expect("any key length works for HMAC");
    m.update(sid);
    m.finalize().into_bytes()[..4].try_into().expect("4 <= 32")
}

fn mac(key: &[u8], data: &str) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length works for HMAC");
    m.update(DOMAIN);
    m.update(data.as_bytes());
    m
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

impl Verdict {
    pub fn encode(&self, upstream_key: &[u8]) -> String {
        let act = match self.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Skip => "skip",
        };
        let mode = match self.mode {
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        };
        let mut s = format!("v=1;act={act};mode={mode}");
        if let Some(r) = &self.reason {
            s.push_str(";why=");
            s.push_str(r);
        }
        s.push_str(&format!(";band={};flags={}", self.band, self.flags));
        if let Some(sid) = self.sid {
            s.push_str(";sid=");
            s.push_str(&hex(&sid));
        }
        s.push_str(&format!(
            ";rid={:016x};ts={};rh={}",
            self.request_id,
            self.ts,
            b64::encode_url(&self.request_hash)
        ));
        let tag = mac(upstream_key, &s).finalize().into_bytes();
        s.push_str(";mac=");
        s.push_str(&b64::encode_url(&tag));
        s
    }

    /// What the upstream app calls. `max_age_secs` bounds how long a captured
    /// header stays useful even against the same request line.
    pub fn verify(
        header: Option<&str>,
        upstream_key: &[u8],
        request_hash: &[u8; 12],
        now: u64,
        max_age_secs: u64,
    ) -> Result<Verdict, VerdictError> {
        let header = header.ok_or(VerdictError::Missing)?;
        let (signed, tag) = header.rsplit_once(";mac=").ok_or(VerdictError::Malformed)?;
        let tag = b64::decode_url(tag).map_err(|_| VerdictError::Malformed)?;
        mac(upstream_key, signed)
            .verify_slice(&tag)
            .map_err(|_| VerdictError::BadMac)?;

        let v = Self::parse(signed).ok_or(VerdictError::Malformed)?;
        if &v.request_hash != request_hash {
            return Err(VerdictError::WrongRequest);
        }
        if now.saturating_sub(v.ts) > max_age_secs || v.ts > now + 5 {
            return Err(VerdictError::Stale);
        }
        Ok(v)
    }

    fn parse(s: &str) -> Option<Verdict> {
        let mut it = s.split(';').map(|kv| kv.split_once('='));
        let mut next = |key: &str| match it.next() {
            Some(Some((k, v))) if k == key => Some(v),
            _ => None,
        };
        // fields are in a fixed order, which keeps this simple
        if next("v")? != "1" {
            return None;
        }
        let action = match next("act")? {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            "skip" => Action::Skip,
            _ => return None,
        };
        let mode = match next("mode")? {
            "observe" => Mode::Observe,
            "enforce" => Mode::Enforce,
            _ => return None,
        };
        let rest: Vec<(&str, &str)> = s
            .split(';')
            .skip(3)
            .map(|kv| kv.split_once('='))
            .collect::<Option<_>>()?;
        let get = |k: &str| rest.iter().find(|(key, _)| *key == k).map(|(_, v)| *v);

        Some(Verdict {
            action,
            mode,
            reason: get("why").map(str::to_owned),
            band: get("band")?.parse().ok()?,
            flags: get("flags")?.parse().ok()?,
            sid: match get("sid") {
                Some(h) => Some(unhex::<4>(h)?),
                None => None,
            },
            request_id: u64::from_str_radix(get("rid")?, 16).ok()?,
            ts: get("ts")?.parse().ok()?,
            request_hash: b64::decode_url(get("rh")?).ok()?.try_into().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"upstream secret shared with the app";

    fn sample() -> Verdict {
        Verdict {
            action: Action::Allow,
            mode: Mode::Enforce,
            reason: None,
            band: 1,
            flags: 4,
            sid: Some([0x3f, 0xa9, 0xc2, 0x1e]),
            request_id: 123_456_789,
            ts: 1_760_716_801,
            request_hash: request_hash("POST", "Shop.Example", "/api/cart", Some("a=1")),
        }
    }

    #[test]
    fn roundtrip() {
        let v = sample();
        let h = v.encode(KEY);
        assert!(h.starts_with(
            "v=1;act=allow;mode=enforce;band=1;flags=4;sid=3fa9c21e;rid=00000000075bcd15;"
        ));
        let rh = request_hash("POST", "shop.example", "/api/cart", Some("a=1"));
        assert_eq!(Verdict::verify(Some(&h), KEY, &rh, v.ts + 1, 5).unwrap(), v);
    }

    #[test]
    fn deny_carries_reason() {
        let mut v = sample();
        v.action = Action::Deny;
        v.mode = Mode::Observe;
        v.reason = Some("sp_auth".into());
        v.sid = None;
        let h = v.encode(KEY);
        assert!(h.contains(";why=sp_auth;"));
        assert_eq!(
            Verdict::verify(Some(&h), KEY, &v.request_hash, v.ts, 5).unwrap(),
            v
        );
    }

    #[test]
    fn rejects_forgery_reuse_and_age() {
        let v = sample();
        let h = v.encode(KEY);
        let rh = v.request_hash;

        assert_eq!(
            Verdict::verify(None, KEY, &rh, v.ts, 5),
            Err(VerdictError::Missing)
        );
        assert_eq!(
            Verdict::verify(Some(&h), b"wrong key", &rh, v.ts, 5),
            Err(VerdictError::BadMac)
        );
        let forged = h.replace("act=allow", "act=deny");
        assert_eq!(
            Verdict::verify(Some(&forged), KEY, &rh, v.ts, 5),
            Err(VerdictError::BadMac)
        );

        let other = request_hash("POST", "shop.example", "/api/admin", None);
        assert_eq!(
            Verdict::verify(Some(&h), KEY, &other, v.ts, 5),
            Err(VerdictError::WrongRequest)
        );
        assert_eq!(
            Verdict::verify(Some(&h), KEY, &rh, v.ts + 6, 5),
            Err(VerdictError::Stale)
        );
    }

    #[test]
    fn day_keys_rotate() {
        let root = [1u8; 32];
        let sid = [9u8; 16];
        let a = sid_hash(&day_key(&root, 20_000), &sid);
        let b = sid_hash(&day_key(&root, 20_001), &sid);
        assert_ne!(a, b);
        assert_eq!(a, sid_hash(&day_key(&root, 20_000), &sid));
    }
}
