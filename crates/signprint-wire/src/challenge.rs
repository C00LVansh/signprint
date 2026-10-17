//! Challenge envelope (`cid`). Handed to the browser with a challenge and sent
//! back with the attestation. It holds the server's ephemeral ECDH secret and
//! all the seeds, so issuing a challenge needs no server-side state beyond a
//! spent-set keyed by `id`.

use crate::bind::Tag;
use crate::keys::KeyRing;
use crate::seal::{self, Header, Kind};
use crate::token::Reader;
use crate::{Error, b64};

pub const MAX_CALIBRATION_SEEDS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanvasParams {
    pub known_seed: u32,
    pub calibration_seeds: Vec<u32>,
    pub rounds: u8,
    pub size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pow {
    None,
    Argon2id {
        memory_kib: u32,
        iterations: u8,
        puzzles: u8,
        bits: u8,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct Challenge {
    pub id: [u8; 16],
    pub issued_at: u32,
    pub expires_at: u32,
    pub ephemeral_secret: [u8; 32],
    pub bind_net: Tag,
    pub bind_ja4: Tag,
    pub canvas: CanvasParams,
    pub probe_seed: u64,
    pub probe_subset: u16,
    pub pow: Pow,
    pub pack_set_hash: [u8; 8],
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Challenge")
            .field("id", &b64::encode_url(&self.id))
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("canvas", &self.canvas)
            .field("pow", &self.pow)
            .finish_non_exhaustive()
    }
}

impl Challenge {
    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(self.canvas.calibration_seeds.len() <= MAX_CALIBRATION_SEEDS);
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.ephemeral_secret);
        out.extend_from_slice(&self.bind_net);
        out.extend_from_slice(&self.bind_ja4);

        let c = &self.canvas;
        out.extend_from_slice(&c.known_seed.to_be_bytes());
        out.push(c.calibration_seeds.len() as u8);
        for s in &c.calibration_seeds {
            out.extend_from_slice(&s.to_be_bytes());
        }
        out.push(c.rounds);
        out.extend_from_slice(&c.size.to_be_bytes());

        out.extend_from_slice(&self.probe_seed.to_be_bytes());
        out.extend_from_slice(&self.probe_subset.to_be_bytes());
        match self.pow {
            Pow::None => out.push(0),
            Pow::Argon2id {
                memory_kib,
                iterations,
                puzzles,
                bits,
            } => {
                out.push(1);
                out.extend_from_slice(&memory_kib.to_be_bytes());
                out.extend_from_slice(&[iterations, puzzles, bits]);
            }
        }
        out.extend_from_slice(&self.pack_set_hash);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        const FIXED_HEAD: usize = 16 + 4 + 4 + 32 + 8 + 8 + 4 + 1;
        if b.len() < FIXED_HEAD {
            return Err(Error::Truncated);
        }
        let n_cal = b[FIXED_HEAD - 1] as usize;
        if n_cal > MAX_CALIBRATION_SEEDS {
            return Err(Error::Malformed("calibration seed count"));
        }
        let pow_at = FIXED_HEAD + 4 * n_cal + 1 + 2 + 8 + 2;
        let pow_len = match b.get(pow_at) {
            Some(0) => 1,
            Some(1) => 8,
            Some(_) => return Err(Error::Malformed("pow kind")),
            None => return Err(Error::Truncated),
        };
        if b.len() != pow_at + pow_len + 8 {
            return Err(Error::Malformed("challenge length"));
        }

        let mut r = Reader(b);
        let id = r.array();
        let issued_at = u32::from_be_bytes(r.array());
        let expires_at = u32::from_be_bytes(r.array());
        let ephemeral_secret = r.array();
        let bind_net = r.array();
        let bind_ja4 = r.array();
        let known_seed = u32::from_be_bytes(r.array());
        let _count = r.array::<1>();
        let calibration_seeds = (0..n_cal).map(|_| u32::from_be_bytes(r.array())).collect();
        let rounds = r.array::<1>()[0];
        let size = u16::from_be_bytes(r.array());
        let probe_seed = u64::from_be_bytes(r.array());
        let probe_subset = u16::from_be_bytes(r.array());
        let pow = match r.array::<1>()[0] {
            0 => Pow::None,
            _ => {
                let memory_kib = u32::from_be_bytes(r.array());
                let [iterations, puzzles, bits] = r.array();
                Pow::Argon2id {
                    memory_kib,
                    iterations,
                    puzzles,
                    bits,
                }
            }
        };
        let pack_set_hash = r.array();

        Ok(Self {
            id,
            issued_at,
            expires_at,
            ephemeral_secret,
            bind_net,
            bind_ja4,
            canvas: CanvasParams {
                known_seed,
                calibration_seeds,
                rounds,
                size,
            },
            probe_seed,
            probe_subset,
            pow,
            pack_set_hash,
        })
    }

    pub fn seal(&self, ring: &KeyRing, nonce: [u8; seal::NONCE_LEN]) -> String {
        let header = Header {
            kind: Kind::Challenge,
            kid: ring.current_kid(),
            host_id: ring.host_id(),
            nonce,
        };
        b64::encode_url(&seal::seal(
            &ring.current().seal_challenge,
            &header,
            &self.to_bytes(),
        ))
    }

    pub fn open(ring: &KeyRing, encoded: &str) -> Result<Self, Error> {
        if encoded.len() > 512 {
            return Err(Error::Malformed("challenge length"));
        }
        let raw = b64::decode_url(encoded)?;
        let header = Header::peek(&raw, Kind::Challenge)?;
        let keys = ring.get(header.kid).ok_or(Error::UnknownKid(header.kid))?;
        let plain = seal::open(&keys.seal_challenge, &raw, Kind::Challenge, ring.host_id())?;
        Self::from_bytes(&plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pow: Pow, seeds: Vec<u32>) -> Challenge {
        Challenge {
            id: [1; 16],
            issued_at: 100,
            expires_at: 160,
            ephemeral_secret: [2; 32],
            bind_net: [3; 8],
            bind_ja4: [4; 8],
            canvas: CanvasParams {
                known_seed: 0xdead_beef,
                calibration_seeds: seeds,
                rounds: 3,
                size: 240,
            },
            probe_seed: 42,
            probe_subset: 5,
            pow,
            pack_set_hash: [6; 8],
        }
    }

    #[test]
    fn roundtrips() {
        let pows = [
            Pow::None,
            Pow::Argon2id {
                memory_kib: 16384,
                iterations: 1,
                puzzles: 4,
                bits: 4,
            },
        ];
        for pow in pows {
            for seeds in [vec![], vec![7], vec![7, 8]] {
                let c = sample(pow, seeds);
                assert_eq!(Challenge::from_bytes(&c.to_bytes()).unwrap(), c);
            }
        }
    }

    #[test]
    fn token_and_challenge_dont_mix() {
        let ring = KeyRing::new(1, 1, &[(1, [9; 32])]).unwrap();
        let cid = sample(Pow::None, vec![]).seal(&ring, [0; 24]);
        assert!(crate::token::SessionToken::open(&ring, &cid).is_err());
        assert!(Challenge::open(&ring, &cid).is_ok());
    }

    #[test]
    fn rejects_bad_lengths() {
        let mut b = sample(Pow::None, vec![1]).to_bytes();
        b.push(0);
        assert!(Challenge::from_bytes(&b).is_err());
        assert!(Challenge::from_bytes(&b[..40]).is_err());
    }
}
