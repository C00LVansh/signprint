//! Sliding anti-replay window, the same idea as IPsec's (RFC 4303 §3.4.3).
//!
//! Requests from one tab can arrive out of order over HTTP/2, so a plain
//! "counter must increase" check would reject legitimate traffic. The window
//! remembers the highest counter seen plus a bitmap of the 127 below it.

pub const WINDOW: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Fresh,
    Replayed,
    TooOld,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    top: u64,
    /// bit i set => counter (top - i) was seen
    seen: u128,
    started: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks `ctr` and records it if it's fresh. Only call this after the
    /// request's MAC has verified, or forged requests could burn slots.
    pub fn check_and_set(&mut self, ctr: u64) -> Verdict {
        if !self.started {
            self.started = true;
            self.top = ctr;
            self.seen = 1;
            return Verdict::Fresh;
        }

        if ctr > self.top {
            let shift = ctr - self.top;
            self.seen = if shift >= WINDOW { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.top = ctr;
            return Verdict::Fresh;
        }

        let age = self.top - ctr;
        if age >= WINDOW {
            return Verdict::TooOld;
        }
        let bit = 1u128 << age;
        if self.seen & bit != 0 {
            return Verdict::Replayed;
        }
        self.seen |= bit;
        Verdict::Fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_and_replay() {
        let mut w = ReplayWindow::new();
        for i in 0..300 {
            assert_eq!(w.check_and_set(i), Verdict::Fresh);
        }
        assert_eq!(w.check_and_set(299), Verdict::Replayed);
        assert_eq!(w.check_and_set(250), Verdict::Replayed);
    }

    #[test]
    fn out_of_order_inside_window() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_set(10), Verdict::Fresh);
        assert_eq!(w.check_and_set(12), Verdict::Fresh);
        assert_eq!(w.check_and_set(11), Verdict::Fresh);
        assert_eq!(w.check_and_set(11), Verdict::Replayed);
        assert_eq!(w.check_and_set(5), Verdict::Fresh);
    }

    #[test]
    fn edges() {
        let mut w = ReplayWindow::new();
        w.check_and_set(1000);
        assert_eq!(w.check_and_set(1000 - 127), Verdict::Fresh);
        assert_eq!(w.check_and_set(1000 - 128), Verdict::TooOld);

        // a big jump clears the bitmap entirely
        w.check_and_set(5000);
        assert_eq!(w.check_and_set(4999), Verdict::Fresh);
        assert_eq!(w.check_and_set(1000), Verdict::TooOld);
    }
}
