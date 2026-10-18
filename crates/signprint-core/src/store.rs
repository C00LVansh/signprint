//! Per-session state the proxy has to remember: replay windows (one per tab),
//! request counts, revocations, and spent challenge ids.
//!
//! Everything else about a session lives in the sealed token, so this is the
//! only shared state. [`MemoryStore`] is enough for a single proxy instance.

use std::collections::HashMap;
use std::sync::Mutex;

use signprint_wire::replay::{ReplayWindow, Verdict};

pub type SessionId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    Fresh {
        requests: u64,
    },
    Replayed,
    TooOld,
    TooManyTabs,
    Revoked,
    /// The store is full. We refuse new sessions rather than evict old
    /// windows, since an evicted window would let its requests be replayed.
    Full,
}

pub trait Store: Send + Sync {
    /// Records request `(tab, ctr)` for `sid` and bumps the request count.
    /// Call only after the request's MAC has verified.
    fn record_request(
        &self,
        sid: &SessionId,
        tab: u32,
        ctr: u64,
        expires_at: u64,
        now: u64,
    ) -> ReplayOutcome;

    /// Marks a challenge id as used. Returns false if it was already spent.
    fn spend_challenge(&self, id: &[u8; 16], expires_at: u64, now: u64) -> bool;

    fn revoke(&self, sid: &SessionId, expires_at: u64);

    fn is_revoked(&self, sid: &SessionId, now: u64) -> bool;
}

impl<T: Store + ?Sized> Store for std::sync::Arc<T> {
    fn record_request(
        &self,
        sid: &SessionId,
        tab: u32,
        ctr: u64,
        expires_at: u64,
        now: u64,
    ) -> ReplayOutcome {
        (**self).record_request(sid, tab, ctr, expires_at, now)
    }
    fn spend_challenge(&self, id: &[u8; 16], expires_at: u64, now: u64) -> bool {
        (**self).spend_challenge(id, expires_at, now)
    }
    fn revoke(&self, sid: &SessionId, expires_at: u64) {
        (**self).revoke(sid, expires_at)
    }
    fn is_revoked(&self, sid: &SessionId, now: u64) -> bool {
        (**self).is_revoked(sid, now)
    }
}

#[derive(Debug)]
struct Session {
    expires_at: u64,
    revoked: bool,
    requests: u64,
    tabs: Vec<(u32, ReplayWindow)>,
}

#[derive(Debug, Default)]
struct Shard {
    sessions: HashMap<SessionId, Session>,
    spent: HashMap<[u8; 16], u64>,
    ops: u32,
}

impl Shard {
    fn sweep(&mut self, now: u64) {
        self.sessions.retain(|_, s| s.expires_at > now);
        self.spent.retain(|_, exp| *exp > now);
    }

    /// Sweeping on every call would be wasteful; every 1024 ops is plenty.
    fn maybe_sweep(&mut self, now: u64) {
        self.ops = self.ops.wrapping_add(1);
        if self.ops % 1024 == 0 {
            self.sweep(now);
        }
    }
}

const SHARDS: usize = 16;

pub struct MemoryStore {
    shards: [Mutex<Shard>; SHARDS],
    max_sessions_per_shard: usize,
    max_tabs: usize,
}

impl MemoryStore {
    pub fn new(max_sessions: usize, max_tabs: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::default()),
            max_sessions_per_shard: max_sessions.div_ceil(SHARDS).max(1),
            max_tabs,
        }
    }

    fn shard(&self, key: &[u8; 16]) -> std::sync::MutexGuard<'_, Shard> {
        // ids are random, so the first byte spreads evenly
        self.shards[key[0] as usize % SHARDS]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(1_000_000, 8)
    }
}

impl Store for MemoryStore {
    fn record_request(
        &self,
        sid: &SessionId,
        tab: u32,
        ctr: u64,
        expires_at: u64,
        now: u64,
    ) -> ReplayOutcome {
        let mut shard = self.shard(sid);
        shard.maybe_sweep(now);

        if !shard.sessions.contains_key(sid) {
            if shard.sessions.len() >= self.max_sessions_per_shard {
                shard.sweep(now);
                if shard.sessions.len() >= self.max_sessions_per_shard {
                    return ReplayOutcome::Full;
                }
            }
            shard.sessions.insert(
                *sid,
                Session {
                    expires_at,
                    revoked: false,
                    requests: 0,
                    tabs: Vec::new(),
                },
            );
        }
        let session = shard.sessions.get_mut(sid).expect("inserted above");
        if session.revoked {
            return ReplayOutcome::Revoked;
        }

        let window = match session.tabs.iter_mut().find(|(t, _)| *t == tab) {
            Some((_, w)) => w,
            None => {
                if session.tabs.len() >= self.max_tabs {
                    return ReplayOutcome::TooManyTabs;
                }
                session.tabs.push((tab, ReplayWindow::new()));
                &mut session.tabs.last_mut().expect("just pushed").1
            }
        };
        match window.check_and_set(ctr) {
            Verdict::Fresh => {
                session.requests += 1;
                ReplayOutcome::Fresh {
                    requests: session.requests,
                }
            }
            Verdict::Replayed => ReplayOutcome::Replayed,
            Verdict::TooOld => ReplayOutcome::TooOld,
        }
    }

    fn spend_challenge(&self, id: &[u8; 16], expires_at: u64, now: u64) -> bool {
        let mut shard = self.shard(id);
        shard.maybe_sweep(now);
        match shard.spent.get(id) {
            Some(exp) if *exp > now => false,
            _ => {
                shard.spent.insert(*id, expires_at);
                true
            }
        }
    }

    fn revoke(&self, sid: &SessionId, expires_at: u64) {
        let mut shard = self.shard(sid);
        let entry = shard.sessions.entry(*sid).or_insert(Session {
            expires_at,
            revoked: true,
            requests: 0,
            tabs: Vec::new(),
        });
        entry.revoked = true;
    }

    fn is_revoked(&self, sid: &SessionId, now: u64) -> bool {
        let shard = self.shard(sid);
        shard
            .sessions
            .get(sid)
            .is_some_and(|s| s.revoked && s.expires_at > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: SessionId = [1; 16];

    #[test]
    fn replay_per_tab() {
        let s = MemoryStore::default();
        assert_eq!(
            s.record_request(&SID, 1, 0, 100, 0),
            ReplayOutcome::Fresh { requests: 1 }
        );
        assert_eq!(
            s.record_request(&SID, 2, 0, 100, 0),
            ReplayOutcome::Fresh { requests: 2 }
        );
        assert_eq!(
            s.record_request(&SID, 1, 0, 100, 0),
            ReplayOutcome::Replayed
        );
        assert_eq!(
            s.record_request(&SID, 1, 1, 100, 0),
            ReplayOutcome::Fresh { requests: 3 }
        );
    }

    #[test]
    fn tab_cap() {
        let s = MemoryStore::new(10, 2);
        s.record_request(&SID, 1, 0, 100, 0);
        s.record_request(&SID, 2, 0, 100, 0);
        assert_eq!(
            s.record_request(&SID, 3, 0, 100, 0),
            ReplayOutcome::TooManyTabs
        );
    }

    #[test]
    fn full_store_refuses_new_sessions() {
        let s = MemoryStore::new(SHARDS, 8); // one session per shard
        assert!(matches!(
            s.record_request(&[0; 16], 1, 0, 100, 0),
            ReplayOutcome::Fresh { .. }
        ));
        assert_eq!(
            s.record_request(&[16; 16], 1, 0, 100, 0),
            ReplayOutcome::Full
        );
        // once the first one expires there's room again
        assert!(matches!(
            s.record_request(&[16; 16], 1, 0, 300, 200),
            ReplayOutcome::Fresh { .. }
        ));
    }

    #[test]
    fn challenges_spend_once() {
        let s = MemoryStore::default();
        assert!(s.spend_challenge(&[9; 16], 60, 0));
        assert!(!s.spend_challenge(&[9; 16], 60, 10));
        assert!(
            s.spend_challenge(&[9; 16], 200, 61),
            "expired entries don't block"
        );
    }

    #[test]
    fn revocation() {
        let s = MemoryStore::default();
        s.record_request(&SID, 1, 0, 100, 0);
        s.revoke(&SID, 100);
        assert!(s.is_revoked(&SID, 50));
        assert_eq!(
            s.record_request(&SID, 1, 1, 100, 50),
            ReplayOutcome::Revoked
        );
        assert!(!s.is_revoked(&SID, 150));
    }
}
