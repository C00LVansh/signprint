//! Proof-of-work ticket. When an attestation scores high enough to need a
//! step-up, the session token is minted but handed out sealed inside one of
//! these, together with the puzzle parameters. Solving the puzzle is the only
//! way to get the token back out.
//!
//! Plaintext layout:
//!
//! ```text
//! id 16 | iat u32 | exp u32 | memory_kib u32 | iterations u8 | puzzles u8 | bits u8 |
//! token_len u16 | token (base64url session token)
//! ```

use crate::keys::KeyRing;
use crate::seal::{self, Header, Kind};
use crate::{Error, b64};

#[derive(Clone, PartialEq, Eq)]
pub struct PowTicket {
    pub id: [u8; 16],
    pub issued_at: u32,
    pub expires_at: u32,
    pub memory_kib: u32,
    pub iterations: u8,
    pub puzzles: u8,
    /// Leading zero bits each puzzle's hash needs.
    pub bits: u8,
    /// The sealed session token this ticket releases.
    pub token: String,
}

impl std::fmt::Debug for PowTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PowTicket")
            .field("id", &b64::encode_url(&self.id))
            .field("expires_at", &self.expires_at)
            .field("memory_kib", &self.memory_kib)
            .field("puzzles", &self.puzzles)
            .field("bits", &self.bits)
            .finish_non_exhaustive()
    }
}

impl PowTicket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(35 + self.token.len());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.memory_kib.to_be_bytes());
        out.extend_from_slice(&[self.iterations, self.puzzles, self.bits]);
        out.extend_from_slice(&(self.token.len() as u16).to_be_bytes());
        out.extend_from_slice(self.token.as_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        const HEAD: usize = 16 + 4 + 4 + 4 + 3 + 2;
        if b.len() < HEAD {
            return Err(Error::Truncated);
        }
        let token_len = u16::from_be_bytes([b[HEAD - 2], b[HEAD - 1]]) as usize;
        if b.len() != HEAD + token_len {
            return Err(Error::Malformed("pow ticket length"));
        }
        let u32_at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().expect("4 bytes"));
        Ok(Self {
            id: b[..16].try_into().expect("16 bytes"),
            issued_at: u32_at(16),
            expires_at: u32_at(20),
            memory_kib: u32_at(24),
            iterations: b[28],
            puzzles: b[29],
            bits: b[30],
            token: String::from_utf8(b[HEAD..].to_vec())
                .map_err(|_| Error::Malformed("pow ticket token"))?,
        })
    }

    pub fn seal(&self, ring: &KeyRing, nonce: [u8; seal::NONCE_LEN]) -> String {
        let header = Header {
            kind: Kind::Pow,
            kid: ring.current_kid(),
            host_id: ring.host_id(),
            nonce,
        };
        b64::encode_url(&seal::seal(
            &ring.current().seal_pow,
            &header,
            &self.to_bytes(),
        ))
    }

    pub fn open(ring: &KeyRing, encoded: &str) -> Result<Self, Error> {
        if encoded.len() > 1024 {
            return Err(Error::Malformed("pow ticket length"));
        }
        let raw = b64::decode_url(encoded)?;
        let header = Header::peek(&raw, Kind::Pow)?;
        let keys = ring.get(header.kid).ok_or(Error::UnknownKid(header.kid))?;
        Self::from_bytes(&seal::open(
            &keys.seal_pow,
            &raw,
            Kind::Pow,
            ring.host_id(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PowTicket {
        PowTicket {
            id: [7; 16],
            issued_at: 100,
            expires_at: 280,
            memory_kib: 16384,
            iterations: 1,
            puzzles: 4,
            bits: 4,
            token: "AgEB".repeat(40),
        }
    }

    #[test]
    fn roundtrip() {
        let ring = KeyRing::new(1, 1, &[(1, [4; 32])]).unwrap();
        let t = sample();
        assert_eq!(PowTicket::from_bytes(&t.to_bytes()).unwrap(), t);
        assert_eq!(PowTicket::open(&ring, &t.seal(&ring, [0; 24])).unwrap(), t);
    }

    #[test]
    fn not_interchangeable_with_tokens() {
        let ring = KeyRing::new(1, 1, &[(1, [4; 32])]).unwrap();
        let sealed = sample().seal(&ring, [0; 24]);
        assert!(crate::token::SessionToken::open(&ring, &sealed).is_err());
        assert!(crate::challenge::Challenge::open(&ring, &sealed).is_err());
    }
}
