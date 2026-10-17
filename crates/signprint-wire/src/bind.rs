//! Short keyed tags used to bind a session to things we only want to compare,
//! never store: the JA4 fingerprint, the client's network prefix, and the
//! fingerprint subset re-checked on refresh.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const TAG_LEN: usize = 8;

pub type Tag = [u8; TAG_LEN];

pub fn tag(bind_key: &[u8; 32], label: &str, value: &[u8]) -> Tag {
    let mut mac = Hmac::<Sha256>::new_from_slice(bind_key).expect("any key length works for HMAC");
    mac.update(label.as_bytes());
    mac.update(&[0]);
    mac.update(value);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

pub fn tags_equal(a: &Tag, b: &Tag) -> bool {
    a.ct_eq(b).into()
}

/// Network prefix used for binding: /24 for IPv4, /48 for IPv6.
pub fn ip_prefix(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            vec![4, o[0], o[1], o[2]]
        }
        std::net::IpAddr::V6(v6) => {
            let mut out = vec![6];
            out.extend_from_slice(&v6.octets()[..6]);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn prefixes() {
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "203.0.113.200".parse().unwrap();
        let c: IpAddr = "203.0.114.7".parse().unwrap();
        assert_eq!(ip_prefix(a), ip_prefix(b));
        assert_ne!(ip_prefix(a), ip_prefix(c));

        let v6a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:1:ffff::9".parse().unwrap();
        assert_eq!(ip_prefix(v6a), ip_prefix(v6b));
    }

    #[test]
    fn labels_separate_domains() {
        let k = [5u8; 32];
        assert_ne!(tag(&k, "net", b"x"), tag(&k, "ja4n", b"x"));
        assert!(tags_equal(&tag(&k, "fp", b"x"), &tag(&k, "fp", b"x")));
    }
}
