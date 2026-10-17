//! The session token. It travels in the `keyid` of every signed request and in
//! the `__Host-sp` cookie, so it carries everything the proxy needs to verify a
//! request without a database lookup, including the session MAC key itself.
//!
//! Plaintext layout (102 bytes, big-endian):
//!
//! ```text
//! sid 16 | iat u32 | exp u32 | epoch u16 | mac_key 32 | client_key_hash 16 |
//! bind_ja4 8 | bind_net 8 | fp_digest 8 | band u8 | flags u8 | policy u16
//! ```

use crate::bind::Tag;
use crate::keys::KeyRing;
use crate::seal::{self, Header, Kind};
use crate::{Error, b64};

pub const PLAINTEXT_LEN: usize = 102;
pub const SEALED_LEN: usize = seal::HEADER_LEN + PLAINTEXT_LEN + seal::TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    pub const NET_ABSENT: u8 = 1 << 0;
    pub const POW_PASSED: u8 = 1 << 1;
    pub const CANVAS_ENFORCED: u8 = 1 << 2;
    pub const SESSION_MODE: u8 = 1 << 3;

    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    pub fn with(self, bit: u8) -> Self {
        Self(self.0 | bit)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub sid: [u8; 16],
    pub issued_at: u32,
    pub expires_at: u32,
    pub epoch: u16,
    pub mac_key: [u8; 32],
    pub client_key_hash: [u8; 16],
    pub bind_ja4: Tag,
    pub bind_net: Tag,
    pub fp_digest: Tag,
    pub band: u8,
    pub flags: Flags,
    pub policy: u16,
}

// mac_key must never end up in logs.
impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken")
            .field("sid", &b64::encode_url(&self.sid))
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("epoch", &self.epoch)
            .field("band", &self.band)
            .field("flags", &self.flags)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl SessionToken {
    pub fn to_bytes(&self) -> [u8; PLAINTEXT_LEN] {
        let mut w = Writer::<PLAINTEXT_LEN>::new();
        w.put(&self.sid);
        w.put(&self.issued_at.to_be_bytes());
        w.put(&self.expires_at.to_be_bytes());
        w.put(&self.epoch.to_be_bytes());
        w.put(&self.mac_key);
        w.put(&self.client_key_hash);
        w.put(&self.bind_ja4);
        w.put(&self.bind_net);
        w.put(&self.fp_digest);
        w.put(&[self.band, self.flags.0]);
        w.put(&self.policy.to_be_bytes());
        w.finish()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != PLAINTEXT_LEN {
            return Err(Error::Malformed("session token length"));
        }
        let mut r = Reader(b);
        Ok(Self {
            sid: r.array(),
            issued_at: u32::from_be_bytes(r.array()),
            expires_at: u32::from_be_bytes(r.array()),
            epoch: u16::from_be_bytes(r.array()),
            mac_key: r.array(),
            client_key_hash: r.array(),
            bind_ja4: r.array(),
            bind_net: r.array(),
            fp_digest: r.array(),
            band: r.array::<1>()[0],
            flags: Flags(r.array::<1>()[0]),
            policy: u16::from_be_bytes(r.array()),
        })
    }

    /// Seals with the ring's current kid. `nonce` must be fresh random bytes.
    pub fn seal(&self, ring: &KeyRing, nonce: [u8; seal::NONCE_LEN]) -> String {
        let header = Header {
            kind: Kind::Token,
            kid: ring.current_kid(),
            host_id: ring.host_id(),
            nonce,
        };
        b64::encode_url(&seal::seal(&ring.current().seal_token, &header, &self.to_bytes()))
    }

    pub fn open(ring: &KeyRing, encoded: &str) -> Result<Self, Error> {
        // cheap length check before decoding anything an attacker sent us
        if encoded.len() > SEALED_LEN * 4 / 3 + 4 {
            return Err(Error::Malformed("session token length"));
        }
        let raw = b64::decode_url(encoded)?;
        let header = Header::peek(&raw, Kind::Token)?;
        let keys = ring.get(header.kid).ok_or(Error::UnknownKid(header.kid))?;
        let plain = seal::open(&keys.seal_token, &raw, Kind::Token, ring.host_id())?;
        Self::from_bytes(&plain)
    }

    pub fn is_expired(&self, now: u32) -> bool {
        now >= self.expires_at
    }
}

pub(crate) struct Writer<const N: usize> {
    buf: [u8; N],
    at: usize,
}

impl<const N: usize> Writer<N> {
    pub(crate) fn new() -> Self {
        Self { buf: [0; N], at: 0 }
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) {
        self.buf[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }

    pub(crate) fn finish(self) -> [u8; N] {
        assert_eq!(self.at, N, "layout doesn't fill the buffer");
        self.buf
    }
}

/// Reader over a slice whose total length was already checked.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl Reader<'_> {
    pub(crate) fn array<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SessionToken {
        SessionToken {
            sid: [1; 16],
            issued_at: 1_760_716_800,
            expires_at: 1_760_717_400,
            epoch: 0,
            mac_key: [2; 32],
            client_key_hash: [3; 16],
            bind_ja4: [4; 8],
            bind_net: [5; 8],
            fp_digest: [6; 8],
            band: 1,
            flags: Flags::default().with(Flags::POW_PASSED),
            policy: 7,
        }
    }

    #[test]
    fn bytes_roundtrip() {
        let t = sample();
        assert_eq!(SessionToken::from_bytes(&t.to_bytes()).unwrap(), t);
    }

    #[test]
    fn seal_roundtrip_and_size() {
        let ring = KeyRing::new(1, 1, &[(1, [9; 32])]).unwrap();
        let s = sample().seal(&ring, [0; 24]);
        assert_eq!(s.len(), 196);
        assert_eq!(SessionToken::open(&ring, &s).unwrap(), sample());
    }

    #[test]
    fn old_kid_still_opens_after_rotation() {
        let old = KeyRing::new(1, 1, &[(1, [9; 32])]).unwrap();
        let s = sample().seal(&old, [0; 24]);
        let rotated = KeyRing::new(1, 2, &[(1, [9; 32]), (2, [8; 32])]).unwrap();
        assert!(SessionToken::open(&rotated, &s).is_ok());

        let mut revoked = rotated.clone();
        revoked.revoke(1);
        assert_eq!(SessionToken::open(&revoked, &s), Err(Error::UnknownKid(1)));
    }

    #[test]
    fn debug_hides_key() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("mac_key"));
    }
}
