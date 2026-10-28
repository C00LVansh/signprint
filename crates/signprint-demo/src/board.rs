//! Scoreboard: what each session managed to get out of the demo.
//!
//! Sessions are identified only by the day-keyed hash in the verdict, so
//! nothing here identifies a person, and it all lives in memory.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

pub const MAX_SESSIONS: usize = 10_000;

#[derive(Debug, Clone, Default, Serialize)]
pub struct SessionStats {
    pub sid: String,
    pub band: u8,
    pub pow: bool,
    pub requests: u64,
    pub products: u64,
    pub pages: BTreeSet<u32>,
    pub logins_ok: u64,
    pub logins_blocked: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Totals {
    pub sessions: usize,
    pub requests: u64,
    pub products_served: u64,
    pub products_to_high_bands: u64,
    pub rejected_without_verdict: u64,
}

#[derive(Debug, Default)]
pub struct Board {
    sessions: HashMap<String, SessionStats>,
    pub totals: Totals,
}

impl Board {
    pub fn session(&mut self, sid: &str, band: u8, pow: bool, now: u64) -> &mut SessionStats {
        let is_new = !self.sessions.contains_key(sid);
        if is_new && self.sessions.len() >= MAX_SESSIONS {
            // drop the quietest session to make room
            if let Some(k) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| (s.requests, s.last_seen))
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&k);
            }
        }
        self.totals.requests += 1;
        self.totals.sessions = self.sessions.len() + usize::from(is_new);
        let s = self
            .sessions
            .entry(sid.to_owned())
            .or_insert_with(|| SessionStats {
                sid: sid.to_owned(),
                first_seen: now,
                ..Default::default()
            });
        s.band = band;
        s.pow |= pow;
        s.last_seen = now;
        s.requests += 1;
        s
    }

    /// Sessions ordered by how much of the catalogue they got.
    pub fn top(&self, n: usize) -> Vec<&SessionStats> {
        let mut v: Vec<&SessionStats> = self.sessions.values().collect();
        v.sort_by(|a, b| {
            b.pages
                .len()
                .cmp(&a.pages.len())
                .then(b.last_seen.cmp(&a.last_seen))
        });
        v.truncate(n);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_and_ranks() {
        let mut b = Board::default();
        b.session("aaaa", 0, false, 1).pages.insert(1);
        let s = b.session("bbbb", 3, true, 2);
        s.pages.extend([1, 2, 3]);
        s.products += 60;
        assert_eq!(b.totals.sessions, 2);
        assert_eq!(b.totals.requests, 2);
        let top = b.top(10);
        assert_eq!(top[0].sid, "bbbb");
        assert!(top[0].pow);
    }

    #[test]
    fn bounded() {
        let mut b = Board::default();
        for i in 0..MAX_SESSIONS + 5 {
            b.session(&format!("{i:08x}"), 0, false, i as u64);
        }
        assert_eq!(b.totals.sessions, MAX_SESSIONS);
    }
}
