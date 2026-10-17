//! The `signprint/1` profile of RFC 9421 HTTP Message Signatures.
//!
//! The profile is narrow on purpose: one label (`sp`), a fixed list of covered
//! components, fixed parameters in a fixed order, HMAC-SHA256 only. Anything
//! else is rejected rather than interpreted, which leaves no room for the
//! signer and verifier to disagree about what was signed.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::nonce::RequestNonce;
use crate::{Error, b64};

pub const LABEL: &str = "sp";
pub const TAG: &str = "signprint/1";
pub const MAC_LEN: usize = 32;

const BASE_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", "@query"];
const BODY_COMPONENT: &str = "content-digest";
const PARAM_ORDER: [&str; 4] = ["created", "keyid", "nonce", "tag"];

/// The request as the signature sees it. All values must already be
/// canonical; see [`canonical_authority`], [`canonical_path`],
/// [`canonical_query`].
#[derive(Debug, Clone, Copy)]
pub struct Components<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    /// Always starts with `?`; just `"?"` when the URL has no query.
    pub query: &'a str,
    /// The `Content-Digest` field value, present iff the request has a body.
    pub content_digest: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub created: u64,
    /// The sealed session token.
    pub keyid: String,
    pub nonce: RequestNonce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub params: Params,
    pub covers_body: bool,
    pub mac: [u8; MAC_LEN],
}

/// The `@signature-params` value, which also goes on the wire after `sp=` in
/// `Signature-Input`.
pub fn signature_params(params: &Params, covers_body: bool) -> String {
    let mut s = String::from("(");
    for (i, c) in BASE_COMPONENTS.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push('"');
        s.push_str(c);
        s.push('"');
    }
    if covers_body {
        s.push_str(" \"");
        s.push_str(BODY_COMPONENT);
        s.push('"');
    }
    s.push(')');
    s.push_str(&format!(
        ";created={};keyid=\"{}\";nonce=\"{}\";tag=\"{}\"",
        params.created, params.keyid, params.nonce, TAG
    ));
    s
}

pub fn signature_base(c: &Components<'_>, params: &Params) -> String {
    let mut base = String::with_capacity(256 + params.keyid.len() * 2);
    for (name, value) in [
        ("@method", c.method),
        ("@authority", c.authority),
        ("@path", c.path),
        ("@query", c.query),
    ] {
        push_line(&mut base, name, value);
    }
    if let Some(d) = c.content_digest {
        push_line(&mut base, BODY_COMPONENT, d);
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(&signature_params(params, c.content_digest.is_some()));
    base
}

fn push_line(base: &mut String, name: &str, value: &str) {
    base.push('"');
    base.push_str(name);
    base.push_str("\": ");
    base.push_str(value);
    base.push('\n');
}

pub fn mac(key: &[u8; 32], base: &str) -> [u8; MAC_LEN] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length works for HMAC");
    m.update(base.as_bytes());
    m.finalize().into_bytes().into()
}

pub fn verify_mac(key: &[u8; 32], base: &str, tag: &[u8; MAC_LEN]) -> bool {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length works for HMAC");
    m.update(base.as_bytes());
    m.verify_slice(tag).is_ok()
}

/// Values for the `Signature-Input` and `Signature` headers.
pub fn header_values(params: &Params, covers_body: bool, mac: &[u8; MAC_LEN]) -> (String, String) {
    (
        format!("{LABEL}={}", signature_params(params, covers_body)),
        format!("{LABEL}=:{}:", b64::encode_std(mac)),
    )
}

/// Pulls our signature out of the two headers. Other labels in the same
/// dictionaries (e.g. a Web Bot Auth signature) are ignored.
pub fn parse(signature_input: &str, signature: &str) -> Result<Received, Error> {
    let bad = |what| Error::Malformed(what);

    let inputs: sfv::Dictionary = sfv::Parser::new(signature_input)
        .parse()
        .map_err(|_| bad("signature-input"))?;
    let Some(sfv::ListEntry::InnerList(list)) = inputs.get(LABEL) else {
        return Err(bad("signature-input"));
    };

    let mut names = Vec::with_capacity(list.items.len());
    for item in &list.items {
        if !item.params.is_empty() {
            return Err(bad("component parameters"));
        }
        let name = item.bare_item.as_string().ok_or(bad("component name"))?;
        names.push(name.as_str());
    }
    let covers_body = if names == BASE_COMPONENTS {
        false
    } else if names.len() == 5 && names[..4] == BASE_COMPONENTS && names[4] == BODY_COMPONENT {
        true
    } else {
        return Err(bad("covered components"));
    };

    let keys: Vec<&str> = list.params.keys().map(|k| k.as_str()).collect();
    if keys != PARAM_ORDER {
        return Err(bad("signature parameters"));
    }
    let created = list.params["created"]
        .as_integer()
        .map(i64::from)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(bad("created"))?;
    let keyid = list.params["keyid"]
        .as_string()
        .ok_or(bad("keyid"))?
        .as_str();
    if keyid.is_empty()
        || !keyid
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(bad("keyid"));
    }
    let nonce = list.params["nonce"].as_string().ok_or(bad("nonce"))?;
    let nonce = RequestNonce::parse(nonce.as_str())?;
    let tag = list.params["tag"].as_string().ok_or(bad("tag"))?;
    if tag.as_str() != TAG {
        return Err(bad("tag"));
    }

    let sigs: sfv::Dictionary = sfv::Parser::new(signature)
        .parse()
        .map_err(|_| bad("signature"))?;
    let Some(sfv::ListEntry::Item(sig)) = sigs.get(LABEL) else {
        return Err(bad("signature"));
    };
    let mac: [u8; MAC_LEN] = sig
        .bare_item
        .as_byte_sequence()
        .and_then(|b| b.try_into().ok())
        .ok_or(bad("signature"))?;

    Ok(Received {
        params: Params {
            created,
            keyid: keyid.to_owned(),
            nonce,
        },
        covers_body,
        mac,
    })
}

/// `@authority`: lowercased host, port dropped when it's the scheme default.
pub fn canonical_authority(authority: &str, https: bool) -> Result<String, Error> {
    let bad = || Error::Malformed("authority");
    if authority.is_empty()
        || authority.contains('@')
        || authority
            .bytes()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err(bad());
    }
    let lower = authority.to_ascii_lowercase();
    let (host, port) = if let Some(rest) = lower.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(bad)?;
        let host = &lower[..end + 2];
        match &rest[end + 1..] {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':').ok_or_else(bad)?)),
        }
    } else {
        match lower.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (lower.as_str(), None),
        }
    };
    if host.is_empty() || host.contains(':') && !host.starts_with('[') {
        return Err(bad());
    }
    let default = if https { "443" } else { "80" };
    Ok(match port {
        None => host.to_owned(),
        Some(p) if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) => return Err(bad()),
        Some(p) if p == default => host.to_owned(),
        Some(p) => format!("{host}:{p}"),
    })
}

/// `@path`: the path exactly as sent, `/` if empty. No percent-decoding.
pub fn canonical_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

/// `@query`: `?` followed by the raw query string; just `?` when there isn't one.
pub fn canonical_query(raw_query: Option<&str>) -> String {
    format!("?{}", raw_query.unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        Params {
            created: 1_760_716_800,
            keyid: "AgEBAAE".into(),
            nonce: RequestNonce {
                tab: 0x9f3a1c07,
                ctr: 17,
            },
        }
    }

    #[test]
    fn base_layout() {
        let c = Components {
            method: "POST",
            authority: "shop.example",
            path: "/api/cart",
            query: "?item=42",
            content_digest: Some("sha-256=:abc=:"),
        };
        let expected = "\"@method\": POST\n\
            \"@authority\": shop.example\n\
            \"@path\": /api/cart\n\
            \"@query\": ?item=42\n\
            \"content-digest\": sha-256=:abc=:\n\
            \"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created=1760716800;keyid=\"AgEBAAE\";nonce=\"9f3a1c07.17\";tag=\"signprint/1\"";
        assert_eq!(signature_base(&c, &params()), expected);
    }

    #[test]
    fn headers_roundtrip_through_parse() {
        let mac = [7u8; 32];
        for body in [false, true] {
            let (input, sig) = header_values(&params(), body, &mac);
            let got = parse(&input, &sig).unwrap();
            assert_eq!(got.params, params());
            assert_eq!(got.covers_body, body);
            assert_eq!(got.mac, mac);
        }
    }

    #[test]
    fn ignores_other_labels() {
        let (input, sig) = header_values(&params(), false, &[1; 32]);
        let input = format!("wba=(\"@authority\");created=1;keyid=\"x\", {input}");
        let sig = format!("wba=:AAAA:, {sig}");
        assert!(parse(&input, &sig).is_ok());
    }

    #[test]
    fn rejects_profile_violations() {
        let sig = format!("sp=:{}:", b64::encode_std(&[0; 32]));
        let ok = signature_params(&params(), false);
        let cases = [
            // missing component
            ok.replace(" \"@query\"", ""),
            // reordered
            ok.replace("\"@method\" \"@authority\"", "\"@authority\" \"@method\""),
            // extra parameter
            ok.replace(";tag=", ";alg=\"hmac-sha256\";tag="),
            // params out of order
            ok.replace(
                ";created=1760716800;keyid=\"AgEBAAE\"",
                ";keyid=\"AgEBAAE\";created=1760716800",
            ),
            // wrong tag
            ok.replace("signprint/1", "signprint/2"),
            // non-canonical nonce
            ok.replace("9f3a1c07.17", "9f3a1c07.017"),
            // negative created
            ok.replace("created=1760716800", "created=-1"),
        ];
        for c in cases {
            assert!(parse(&format!("sp={c}"), &sig).is_err(), "accepted {c}");
        }
        assert!(
            parse(&format!("sp={ok}"), "sp=:AAAA:").is_err(),
            "short mac"
        );
    }

    #[test]
    fn mac_verifies() {
        let base = "hello";
        let k = [3u8; 32];
        let t = mac(&k, base);
        assert!(verify_mac(&k, base, &t));
        assert!(!verify_mac(&[4u8; 32], base, &t));
    }

    #[test]
    fn authority_rules() {
        let ok = |a, https, want: &str| assert_eq!(canonical_authority(a, https).unwrap(), want);
        ok("Shop.Example", true, "shop.example");
        ok("shop.example:443", true, "shop.example");
        ok("shop.example:443", false, "shop.example:443");
        ok("shop.example:80", false, "shop.example");
        ok("shop.example:8443", true, "shop.example:8443");
        ok("[2001:DB8::1]:443", true, "[2001:db8::1]");
        ok("[2001:db8::1]:8443", true, "[2001:db8::1]:8443");
        for bad in [
            "",
            "user@shop.example",
            "shop.example:",
            "shop .example",
            "a:b:c",
            "[::1",
        ] {
            assert!(canonical_authority(bad, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn path_and_query() {
        assert_eq!(canonical_path(""), "/");
        assert_eq!(canonical_path("/a%2Fb"), "/a%2Fb");
        assert_eq!(canonical_query(None), "?");
        assert_eq!(canonical_query(Some("")), "?");
        assert_eq!(canonical_query(Some("a=1&b=2")), "?a=1&b=2");
    }
}
