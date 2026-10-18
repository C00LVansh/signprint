//! Network-layer evidence about a request and where it came from.
//!
//! The standalone proxy terminates TLS itself and fills this in directly. When
//! signprint runs behind another proxy, the JA4 has to be forwarded in a header,
//! and we only believe that header if the hop that sent it is one we trust.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// We saw the TLS ClientHello ourselves.
    Direct,
    /// Forwarded by a trusted upstream.
    Forwarded,
    /// No network evidence for this request.
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub peer_ip: IpAddr,
    /// Normalised JA4 (resumption extensions removed), if known.
    pub ja4n: Option<String>,
    pub provenance: Provenance,
}

impl Network {
    pub fn direct(peer_ip: IpAddr, ja4n: Option<String>) -> Self {
        let provenance = if ja4n.is_some() {
            Provenance::Direct
        } else {
            Provenance::Absent
        };
        Self {
            peer_ip,
            ja4n,
            provenance,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl std::str::FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| format!("bad address in {s:?}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse()
                .ok()
                .filter(|p| *p <= max)
                .ok_or(format!("bad prefix in {s:?}"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Middleware mode: accept a forwarded JA4 header only from trusted hops.
#[derive(Debug, Clone, Default)]
pub struct ForwardedTrusted {
    pub trusted: Vec<Cidr>,
}

impl ForwardedTrusted {
    /// `peer_ip` is the address of the connection we actually received.
    /// `forwarded_ja4n` is the header value, if present. From an untrusted
    /// peer it's ignored outright: anyone can set a header.
    pub fn network(&self, peer_ip: IpAddr, forwarded_ja4n: Option<&str>) -> Network {
        let trusted = self.trusted.iter().any(|c| c.contains(peer_ip));
        match forwarded_ja4n {
            Some(j) if trusted && is_plausible_ja4(j) => Network {
                peer_ip,
                ja4n: Some(j.to_owned()),
                provenance: Provenance::Forwarded,
            },
            _ => Network {
                peer_ip,
                ja4n: None,
                provenance: Provenance::Absent,
            },
        }
    }
}

/// JA4 looks like `t13d1516h2_8daaf6152771_02713d6af862`.
fn is_plausible_ja4(s: &str) -> bool {
    s.len() <= 64
        && s.split('_').count() == 3
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matching() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(ip("10.200.3.4")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("::1")));

        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("8.8.8.8")));

        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!(!v6.contains(ip("2001:db9::1")));

        let single: Cidr = "192.0.2.7".parse().unwrap();
        assert!(single.contains(ip("192.0.2.7")));
        assert!(!single.contains(ip("192.0.2.8")));

        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nope/8".parse::<Cidr>().is_err());
    }

    #[test]
    fn forwarded_header_only_from_trusted_hops() {
        let f = ForwardedTrusted {
            trusted: vec!["10.0.0.0/8".parse().unwrap()],
        };
        let ja4 = "t13d1516h2_8daaf6152771_02713d6af862";

        let n = f.network(ip("10.1.2.3"), Some(ja4));
        assert_eq!(n.provenance, Provenance::Forwarded);
        assert_eq!(n.ja4n.as_deref(), Some(ja4));

        let n = f.network(ip("203.0.113.9"), Some(ja4));
        assert_eq!(n.provenance, Provenance::Absent);
        assert_eq!(n.ja4n, None);

        let n = f.network(ip("10.1.2.3"), Some("not a ja4; drop table"));
        assert_eq!(n.provenance, Provenance::Absent);
    }
}
