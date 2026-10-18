//! Known-answer pattern: a few opaque, axis-aligned rectangles on an opaque
//! background, drawn at integer coordinates. A canvas that isn't adding noise
//! returns exactly these pixels, so we can compute the expected hash here
//! without rendering anything.
//!
//! Brave, Firefox's fingerprinting protection and Safari's private mode all
//! perturb readbacks, but their noise is seeded per site and session *and by
//! the canvas contents*, so drawing the same thing twice gives the same noise
//! and can't reveal it. Comparing against a value computed elsewhere can.
//! Every channel is kept away from 0 and 255 because some noise schemes skip
//! pixels with a zero channel.

use sha2::{Digest, Sha256};

use crate::prng::Rng;

pub const WIDTH: u32 = 64;
pub const HEIGHT: u32 = 16;
pub const RECTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub rgb: [u8; 3],
}

fn color(r: &mut Rng) -> [u8; 3] {
    [
        r.range(16, 239) as u8,
        r.range(16, 239) as u8,
        r.range(16, 239) as u8,
    ]
}

/// Background colour followed by the rectangles, in drawing order.
pub fn layout(seed: u32) -> ([u8; 3], Vec<Rect>) {
    let mut r = Rng::new(seed ^ 0x7061_7474); // "patt"
    let bg = color(&mut r);
    let rects = (0..RECTS)
        .map(|_| {
            let x = r.range(0, WIDTH - 8);
            let y = r.range(0, HEIGHT - 4);
            let w = r.range(4, WIDTH - x);
            let h = r.range(2, HEIGHT - y);
            Rect {
                x,
                y,
                w,
                h,
                rgb: color(&mut r),
            }
        })
        .collect();
    (bg, rects)
}

/// The RGBA bytes a noise-free canvas returns for this seed.
pub fn pixels(seed: u32) -> Vec<u8> {
    let (bg, rects) = layout(seed);
    let mut px = Vec::with_capacity((WIDTH * HEIGHT * 4) as usize);
    for _ in 0..WIDTH * HEIGHT {
        px.extend_from_slice(&[bg[0], bg[1], bg[2], 255]);
    }
    for rect in rects {
        for y in rect.y..rect.y + rect.h {
            for x in rect.x..rect.x + rect.w {
                let i = ((y * WIDTH + x) * 4) as usize;
                px[i..i + 3].copy_from_slice(&rect.rgb);
            }
        }
    }
    px
}

/// Hex SHA-256 of the expected pixels, which is what the client reports.
pub fn expected_hash(seed: u32) -> String {
    Sha256::digest(pixels(seed))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rects_stay_on_canvas_and_colours_avoid_extremes() {
        for seed in 0..500 {
            let (bg, rects) = layout(seed);
            assert!(bg.iter().all(|c| (16..=239).contains(c)));
            for r in rects {
                assert!(
                    r.x + r.w <= WIDTH && r.y + r.h <= HEIGHT,
                    "seed {seed}: {r:?}"
                );
                assert!(r.w >= 4 && r.h >= 2);
                assert!(r.rgb.iter().all(|c| (16..=239).contains(c)));
            }
        }
    }

    #[test]
    fn hash_depends_on_seed() {
        assert_ne!(expected_hash(1), expected_hash(2));
        assert_eq!(expected_hash(7), expected_hash(7));
        assert_eq!(pixels(7).len(), (WIDTH * HEIGHT * 4) as usize);
    }
}
