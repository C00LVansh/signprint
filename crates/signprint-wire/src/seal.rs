//! Sealed objects: a small cleartext header followed by XChaCha20-Poly1305
//! ciphertext. The whole header is the AAD, so changing kid, host or kind
//! breaks the tag.
//!
//! ```text
//! version u8 | kind u8 | kid u8 | host_id u16 | nonce [24] | ciphertext+tag
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::Error;
use crate::keys::KEY_LEN;

pub const VERSION: u8 = 2;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = 5 + NONCE_LEN;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Token = 1,
    Challenge = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub kid: u8,
    pub host_id: u16,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = VERSION;
        out[1] = self.kind as u8;
        out[2] = self.kid;
        out[3..5].copy_from_slice(&self.host_id.to_be_bytes());
        out[5..].copy_from_slice(&self.nonce);
        out
    }

    /// Reads the header without authenticating anything. Callers use it to
    /// pick the right key, then must call [`open`].
    pub fn peek(sealed: &[u8], expect: Kind) -> Result<Self, Error> {
        if sealed.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Truncated);
        }
        if sealed[0] != VERSION {
            return Err(Error::UnsupportedVersion(sealed[0]));
        }
        if sealed[1] != expect as u8 {
            return Err(Error::WrongKind);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sealed[5..HEADER_LEN]);
        Ok(Self {
            kind: expect,
            kid: sealed[2],
            host_id: u16::from_be_bytes([sealed[3], sealed[4]]),
            nonce,
        })
    }
}

pub fn seal(key: &[u8; KEY_LEN], header: &Header, plaintext: &[u8]) -> Vec<u8> {
    let aad = header.encode();
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            &XNonce::from(header.nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("encryption with a valid key can't fail");
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct);
    out
}

/// Authenticates and decrypts. `host_id` must match the header, which stops a
/// token minted for one site being replayed against another.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], kind: Kind, host_id: u16) -> Result<Vec<u8>, Error> {
    let header = Header::peek(sealed, kind)?;
    if header.host_id != host_id {
        return Err(Error::WrongHost);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::from(header.nonce),
            Payload {
                msg: &sealed[HEADER_LEN..],
                aad: &sealed[..HEADER_LEN],
            },
        )
        .map_err(|_| Error::BadSeal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: Kind) -> Header {
        Header {
            kind,
            kid: 4,
            host_id: 9,
            nonce: [3; NONCE_LEN],
        }
    }

    #[test]
    fn roundtrip() {
        let key = [1u8; 32];
        let sealed = seal(&key, &header(Kind::Token), b"hello");
        assert_eq!(sealed.len(), HEADER_LEN + 5 + TAG_LEN);
        assert_eq!(open(&key, &sealed, Kind::Token, 9).unwrap(), b"hello");
    }

    #[test]
    fn rejects_tampering_and_confusion() {
        let key = [1u8; 32];
        let mut sealed = seal(&key, &header(Kind::Token), b"hello");

        assert!(matches!(open(&key, &sealed, Kind::Challenge, 9), Err(Error::WrongKind)));
        assert!(matches!(open(&key, &sealed, Kind::Token, 8), Err(Error::WrongHost)));
        assert!(matches!(open(&[2u8; 32], &sealed, Kind::Token, 9), Err(Error::BadSeal)));

        sealed[2] ^= 1; // kid is in the AAD
        assert!(matches!(open(&key, &sealed, Kind::Token, 9), Err(Error::BadSeal)));
    }
}
