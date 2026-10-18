//! JA4 TLS client fingerprints, implemented from FoxIO's published spec
//! (technical_details/JA4.md). JA4 itself is BSD-3-Clause; the rest of the
//! JA4+ family is under a different licence and isn't implemented here.
//!
//! We also produce a normalised variant, `ja4n`, that ignores the TLS
//! resumption extensions (pre_shared_key, early_data). A browser that resumes
//! a session sends those and nothing else changes, so binding a session to
//! plain JA4 would break on the first resumed connection.

use sha2::{Digest, Sha256};

use crate::hello::ClientHello;

const SNI: u16 = 0x0000;
const ALPN: u16 = 0x0010;
const PRE_SHARED_KEY: u16 = 0x0029;
const EARLY_DATA: u16 = 0x002a;

/// GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn alpn_code(first: Option<&[u8]>) -> String {
    let Some(v) = first.filter(|v| !v.is_empty()) else {
        return "00".into();
    };
    let (a, b) = (v[0], v[v.len() - 1]);
    if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
        format!("{}{}", a as char, b as char)
    } else {
        let hex: String = v.iter().map(|x| format!("{x:02x}")).collect();
        let h = hex.as_bytes();
        format!("{}{}", h[0] as char, h[h.len() - 1] as char)
    }
}

fn hash12(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    d[..6].iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_list(v: &[u16]) -> String {
    v.iter()
        .map(|x| format!("{x:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn compute(h: &ClientHello, drop_resumption: bool) -> String {
    let keep =
        |e: &u16| !is_grease(*e) && !(drop_resumption && matches!(*e, PRE_SHARED_KEY | EARLY_DATA));

    let version = h
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(h.legacy_version);

    let mut ciphers: Vec<u16> = h
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts: Vec<u16> = h.extensions.iter().copied().filter(keep).collect();

    let a = format!(
        "t{}{}{:02}{:02}{}",
        version_code(version),
        if h.has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        exts.len().min(99),
        alpn_code(h.alpn_first.as_deref()),
    );

    ciphers.sort_unstable();
    let b = if ciphers.is_empty() {
        "000000000000".into()
    } else {
        hash12(&hex_list(&ciphers))
    };

    let mut sorted: Vec<u16> = exts
        .into_iter()
        .filter(|e| *e != SNI && *e != ALPN)
        .collect();
    sorted.sort_unstable();
    let c = if sorted.is_empty() {
        "000000000000".into()
    } else {
        let sigs: Vec<u16> = h
            .signature_algorithms
            .iter()
            .copied()
            .filter(|s| !is_grease(*s))
            .collect();
        let mut input = hex_list(&sorted);
        if !sigs.is_empty() {
            input.push('_');
            input.push_str(&hex_list(&sigs));
        }
        hash12(&input)
    };

    format!("{a}_{b}_{c}")
}

pub fn ja4(hello: &ClientHello) -> String {
    compute(hello, false)
}

/// JA4 with pre_shared_key and early_data ignored; stable across resumption.
pub fn ja4n(hello: &ClientHello) -> String {
    compute(hello, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::build::*;
    use crate::hello::parse;

    /// The worked example from the JA4 spec, with GREASE sprinkled in.
    fn spec_example(extra: &[u16]) -> ClientHello {
        let ciphers = [
            0x1a1a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let mut exts = vec![
            Ext(0x2a2a, vec![]),
            Ext(0x001b, vec![]),
            sni("example.com"),
            Ext(0x0033, vec![]),
            alpn(&[b"h2", b"http/1.1"]),
            Ext(0x4469, vec![]),
            Ext(0x0017, vec![]),
            Ext(0x002d, vec![]),
            sig_algs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
            Ext(0x0005, vec![]),
            Ext(0x0023, vec![]),
            Ext(0x0012, vec![]),
            versions(&[0x3a3a, 0x0304, 0x0303]),
            Ext(0xff01, vec![]),
            Ext(0x000b, vec![]),
            Ext(0x000a, vec![]),
            Ext(0x0015, vec![]),
        ];
        exts.extend(extra.iter().map(|e| Ext(*e, vec![])));
        parse(&records(&client_hello(&ciphers, &exts), 16384)).unwrap()
    }

    #[test]
    fn matches_spec_example() {
        assert_eq!(
            ja4(&spec_example(&[])),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn normalised_ignores_resumption() {
        let fresh = spec_example(&[]);
        let resumed = spec_example(&[EARLY_DATA, PRE_SHARED_KEY]);
        assert_ne!(ja4(&fresh), ja4(&resumed));
        assert_eq!(ja4n(&fresh), ja4n(&resumed));
        assert_eq!(ja4n(&fresh), ja4(&fresh));
    }

    #[test]
    fn grease_detection() {
        for g in [0x0a0a, 0x1a1a, 0x2a2a, 0xaaaa, 0xfafa] {
            assert!(is_grease(g));
        }
        for n in [0x0a1a, 0x1301, 0x0000, 0xabab] {
            assert!(!is_grease(n));
        }
    }

    #[test]
    fn alpn_rules_from_spec() {
        assert_eq!(alpn_code(None), "00");
        assert_eq!(alpn_code(Some(b"")), "00");
        assert_eq!(alpn_code(Some(b"h2")), "h2");
        assert_eq!(alpn_code(Some(b"http/1.1")), "h1");
        assert_eq!(alpn_code(Some(b"x")), "xx");
        assert_eq!(alpn_code(Some(&[0xab])), "ab");
        assert_eq!(alpn_code(Some(&[0x20])), "20");
        assert_eq!(alpn_code(Some(&[0xab, 0xcd])), "ad");
        assert_eq!(alpn_code(Some(&[0x20, 0x61])), "21");
        assert_eq!(alpn_code(Some(&[0x30, 0xab])), "3b");
        assert_eq!(alpn_code(Some(&[0x61, 0x20])), "60");
        assert_eq!(alpn_code(Some(&[0x30, 0x31, 0xab, 0xcd])), "3d");
        assert_eq!(alpn_code(Some(&[0x30, 0xab, 0xcd, 0x31])), "01");
    }

    #[test]
    fn empty_sections() {
        let h = parse(&records(&client_hello(&[], &[]), 16384)).unwrap();
        assert_eq!(ja4(&h), "t12i000000_000000000000_000000000000");
    }

    #[test]
    fn no_signature_algorithms_means_no_underscore() {
        // spec: "0005,...,ff01 = 6d807ffa2a79"
        let list = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01";
        assert_eq!(hash12(list), "6d807ffa2a79");
    }
}
