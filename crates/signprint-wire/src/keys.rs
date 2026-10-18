//! Key ring: per-kid master secrets and the subkeys derived from them.
//!
//! Every master key gets a one-byte `kid`. Subkeys are derived with HKDF-SHA256,
//! using an info string that includes the deployment's `host_id`, so two sites
//! sharing a key ring still can't open each other's tokens.

use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct Subkeys {
    pub seal_token: [u8; KEY_LEN],
    pub seal_challenge: [u8; KEY_LEN],
    pub seal_pow: [u8; KEY_LEN],
    pub bind: [u8; KEY_LEN],
}

impl Subkeys {
    pub fn derive(master: &[u8; KEY_LEN], host_id: u16) -> Self {
        let hk = Hkdf::<Sha256>::new(None, master);
        Self {
            seal_token: expand(&hk, b"signprint/1 seal-token", host_id),
            seal_challenge: expand(&hk, b"signprint/1 seal-cid", host_id),
            seal_pow: expand(&hk, b"signprint/1 seal-pow", host_id),
            bind: expand(&hk, b"signprint/1 bind", host_id),
        }
    }
}

impl std::fmt::Debug for Subkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Subkeys(..)")
    }
}

fn expand(hk: &Hkdf<Sha256>, label: &[u8], host_id: u16) -> [u8; KEY_LEN] {
    let mut info = Vec::with_capacity(label.len() + 2);
    info.extend_from_slice(label);
    info.extend_from_slice(&host_id.to_be_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Master keys indexed by kid. New tokens are sealed with `current`; older kids
/// stay around until every token they sealed has expired.
#[derive(Debug, Clone)]
pub struct KeyRing {
    host_id: u16,
    current: u8,
    entries: Vec<(u8, Subkeys)>,
}

impl KeyRing {
    pub fn new(host_id: u16, current: u8, masters: &[(u8, [u8; KEY_LEN])]) -> Option<Self> {
        let entries: Vec<_> = masters
            .iter()
            .map(|(kid, m)| (*kid, Subkeys::derive(m, host_id)))
            .collect();
        entries.iter().any(|(k, _)| *k == current).then_some(Self {
            host_id,
            current,
            entries,
        })
    }

    pub fn host_id(&self) -> u16 {
        self.host_id
    }

    pub fn current_kid(&self) -> u8 {
        self.current
    }

    pub fn current(&self) -> &Subkeys {
        self.get(self.current).expect("checked in KeyRing::new")
    }

    pub fn get(&self, kid: u8) -> Option<&Subkeys> {
        self.entries.iter().find(|(k, _)| *k == kid).map(|(_, s)| s)
    }

    /// Drop a kid immediately, e.g. after a suspected leak. Tokens sealed with
    /// it stop opening.
    pub fn revoke(&mut self, kid: u8) -> bool {
        if kid == self.current {
            return false;
        }
        let before = self.entries.len();
        self.entries.retain(|(k, _)| *k != kid);
        self.entries.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_differ_by_purpose_and_host() {
        let m = [7u8; 32];
        let a = Subkeys::derive(&m, 1);
        let b = Subkeys::derive(&m, 2);
        assert_ne!(a.seal_token, a.seal_challenge);
        assert_ne!(a.seal_token, a.bind);
        assert_ne!(a.seal_token, b.seal_token);
    }

    #[test]
    fn keyring_requires_current_kid() {
        assert!(KeyRing::new(1, 3, &[(1, [0; 32])]).is_none());
        let mut ring = KeyRing::new(1, 1, &[(1, [0; 32]), (2, [1; 32])]).unwrap();
        assert!(!ring.revoke(1), "current kid can't be revoked");
        assert!(ring.revoke(2));
        assert!(ring.get(2).is_none());
    }
}
