//! Argon2id proof-of-work puzzles.
//!
//! A ticket has `puzzles` independent sub-puzzles. For each index `i` the client
//! needs a nonce `n` such that
//!
//! ```text
//! Argon2id(password = id || i || n_be32, salt = id || "signprint/1 pow", m, t, p = 1, 32 bytes)
//! ```
//!
//! starts with `bits` zero bits. Several small puzzles instead of one big one
//! keeps the time it takes much more predictable. Argon2id is memory-hard,
//! which keeps the gap between a browser and a GPU or native solver far
//! smaller than with SHA-256 puzzles.
//!
//! This prices a session; it doesn't detect anything.

use argon2::{Algorithm, Argon2, Params, Version};

pub const SALT_SUFFIX: &[u8] = b"signprint/1 pow";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowParams {
    pub memory_kib: u32,
    pub iterations: u8,
    pub puzzles: u8,
    pub bits: u8,
}

pub fn hash(p: &PowParams, id: &[u8; 16], index: u8, nonce: u32) -> Option<[u8; 32]> {
    let params = Params::new(p.memory_kib, p.iterations as u32, 1, Some(32)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut password = [0u8; 21];
    password[..16].copy_from_slice(id);
    password[16] = index;
    password[17..].copy_from_slice(&nonce.to_be_bytes());
    let mut salt = [0u8; 16 + SALT_SUFFIX.len()];
    salt[..16].copy_from_slice(id);
    salt[16..].copy_from_slice(SALT_SUFFIX);

    let mut out = [0u8; 32];
    argon.hash_password_into(&password, &salt, &mut out).ok()?;
    Some(out)
}

pub fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// Checks one nonce per puzzle. Costs `puzzles` Argon2 evaluations, so only
/// call it after the ticket itself has been opened and checked.
pub fn verify(p: &PowParams, id: &[u8; 16], nonces: &[u32]) -> bool {
    if nonces.len() != p.puzzles as usize {
        return false;
    }
    nonces.iter().enumerate().all(|(i, n)| {
        hash(p, id, i as u8, *n).is_some_and(|h| leading_zero_bits(&h) >= p.bits as u32)
    })
}

/// Brute-force solver, for tests and tools. Browsers have their own.
pub fn solve(p: &PowParams, id: &[u8; 16]) -> Vec<u32> {
    (0..p.puzzles)
        .map(|i| {
            (0u32..)
                .find(|n| {
                    hash(p, id, i, *n).is_some_and(|h| leading_zero_bits(&h) >= p.bits as u32)
                })
                .expect("a solution exists well before u32::MAX")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // tiny memory so the tests stay fast
    const P: PowParams = PowParams {
        memory_kib: 64,
        iterations: 1,
        puzzles: 3,
        bits: 4,
    };

    #[test]
    fn zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x10, 0xff]), 19);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn solve_then_verify() {
        let id = [9u8; 16];
        let nonces = solve(&P, &id);
        assert!(verify(&P, &id, &nonces));

        // swap in a nonce that definitely isn't a solution for puzzle 1
        let bad = (0u32..)
            .find(|n| leading_zero_bits(&hash(&P, &id, 1, *n).unwrap()) < 4)
            .unwrap();
        let mut wrong = nonces.clone();
        wrong[1] = bad;
        assert!(!verify(&P, &id, &wrong));

        assert!(!verify(&P, &id, &nonces[..2]), "too few nonces");
        assert!(!verify(&P, &[8u8; 16], &nonces), "bound to the ticket id");
    }
}
