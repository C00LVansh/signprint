//! Request nonces: `"<tab>.<ctr>"`, where `tab` is 8 lowercase hex digits picked
//! by each browser tab and `ctr` is that tab's request counter.
//!
//! Parsing is deliberately strict (no leading zeros, no `+`, fixed-width tab)
//! so there is exactly one valid spelling of any nonce. Otherwise the same
//! (tab, ctr) could be signed under two different strings.

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestNonce {
    pub tab: u32,
    pub ctr: u64,
}

impl RequestNonce {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let bad = || Error::Malformed("nonce");
        let (tab, ctr) = s.split_once('.').ok_or_else(bad)?;

        if tab.len() != 8 || !tab.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad());
        }
        let tab = u32::from_str_radix(tab, 16).map_err(|_| bad())?;

        if ctr.is_empty() || ctr.len() > 20 || !ctr.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        if ctr.len() > 1 && ctr.starts_with('0') {
            return Err(bad());
        }
        let ctr = ctr.parse::<u64>().map_err(|_| bad())?;

        Ok(Self { tab, ctr })
    }
}

impl std::fmt::Display for RequestNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}.{}", self.tab, self.ctr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_forms() {
        let n = RequestNonce::parse("9f3a1c07.17").unwrap();
        assert_eq!(n, RequestNonce { tab: 0x9f3a1c07, ctr: 17 });
        assert_eq!(n.to_string(), "9f3a1c07.17");
        assert_eq!(RequestNonce::parse("00000000.0").unwrap().ctr, 0);
        assert_eq!(
            RequestNonce::parse("ffffffff.18446744073709551615").unwrap().ctr,
            u64::MAX
        );
    }

    #[test]
    fn rejects_alternate_spellings() {
        for s in [
            "9f3a1c07.017",
            "9F3A1C07.17",
            "9f3a1c7.17",
            "9f3a1c07.+17",
            "9f3a1c07.",
            "9f3a1c07",
            "9f3a1c07.18446744073709551616",
            "9f3a1c07.1.2",
            " 9f3a1c07.1",
        ] {
            assert!(RequestNonce::parse(s).is_err(), "{s:?} should be rejected");
        }
    }
}
