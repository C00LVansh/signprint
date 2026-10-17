//! `Content-Digest` (RFC 9530), sha-256 only.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, b64};

pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", b64::encode_std(&Sha256::digest(body)))
}

/// Checks a received `Content-Digest` value against the body bytes. Other
/// algorithms may appear in the dictionary; only sha-256 is checked and it
/// has to be there.
pub fn verify(header_value: &str, body: &[u8]) -> Result<(), Error> {
    let dict: sfv::Dictionary = sfv::Parser::new(header_value)
        .parse()
        .map_err(|_| Error::Malformed("content-digest"))?;
    let claimed = match dict.get("sha-256") {
        Some(sfv::ListEntry::Item(item)) => item
            .bare_item
            .as_byte_sequence()
            .ok_or(Error::Malformed("content-digest"))?,
        _ => return Err(Error::Malformed("content-digest")),
    };
    let actual = Sha256::digest(body);
    if claimed.len() == actual.len() && bool::from(claimed.ct_eq(actual.as_slice())) {
        Ok(())
    } else {
        Err(Error::DigestMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_value() {
        // RFC 9530 appendix B example body
        let body = br#"{"hello": "world"}"#;
        assert_eq!(
            content_digest(body),
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
        );
    }

    #[test]
    fn verify_checks_body() {
        let h = content_digest(b"abc");
        assert!(verify(&h, b"abc").is_ok());
        assert_eq!(verify(&h, b"abd"), Err(Error::DigestMismatch));
        assert!(verify("sha-512=:AAAA:", b"abc").is_err());
        assert!(verify("not a dictionary(", b"abc").is_err());
    }
}
