//! xoshiro128** seeded through splitmix32. Everything is 32-bit so the
//! browser can reproduce it exactly with `Math.imul` and `>>> 0`; the client's
//! `canvas.ts` has the same generator and testvectors/canvas.json pins them
//! together.

#[derive(Debug, Clone)]
pub struct Rng {
    s: [u32; 4],
}

fn splitmix32(state: &mut u32) -> u32 {
    *state = state.wrapping_add(0x9e37_79b9);
    let mut z = *state;
    z = (z ^ (z >> 16)).wrapping_mul(0x85eb_ca6b);
    z = (z ^ (z >> 13)).wrapping_mul(0xc2b2_ae35);
    z ^ (z >> 16)
}

impl Rng {
    pub fn new(seed: u32) -> Self {
        let mut st = seed;
        let s = [
            splitmix32(&mut st),
            splitmix32(&mut st),
            splitmix32(&mut st),
            splitmix32(&mut st),
        ];
        Self { s }
    }

    pub fn next_u32(&mut self) -> u32 {
        let s = &mut self.s;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 9;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(11);
        result
    }

    /// Uniform-ish integer in `lo..=hi` (modulo bias is irrelevant here).
    pub fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.next_u32() % (hi - lo + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_seed_dependent() {
        let a: Vec<u32> = {
            let mut r = Rng::new(1);
            (0..4).map(|_| r.next_u32()).collect()
        };
        let mut r = Rng::new(1);
        let b: Vec<u32> = (0..4).map(|_| r.next_u32()).collect();
        assert_eq!(a, b);
        let mut r2 = Rng::new(2);
        assert_ne!(a[0], r2.next_u32());
    }

    #[test]
    fn range_bounds() {
        let mut r = Rng::new(42);
        for _ in 0..1000 {
            let v = r.range(16, 239);
            assert!((16..=239).contains(&v));
        }
    }
}
