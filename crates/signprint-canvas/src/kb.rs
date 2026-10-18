//! The canvas answer database.
//!
//! For each seed in this deployment's private pool, the set of answers that
//! calibrated devices of each class produced. Answers only get in through
//! calibration (an operator running the calibration flow on real devices),
//! never from ordinary traffic: learning from traffic would let a bot farm
//! that is most of a small site's traffic teach the database its own answers.
//!
//! A class only counts once enough distinct devices have calibrated it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::class::DeviceClass;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ClassEntry {
    /// seed -> answers seen from calibrated devices of this class
    answers: BTreeMap<u32, BTreeSet<String>>,
    /// distinct calibrating devices (random ids the calibration page makes up)
    devices: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Kb {
    pool: Vec<u32>,
    classes: BTreeMap<String, (DeviceClass, ClassEntry)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The class isn't calibrated enough to judge.
    Unknown,
    /// Answer matches what this class produces.
    Match,
    /// Answer isn't one we've seen from this class (new driver, or a lie).
    Mismatch,
    /// Answer is what a *different* class produces: the browser is claiming
    /// to be something it isn't.
    ClassLie,
}

pub const MAX_DEVICES_PER_CLASS: usize = 10_000;
pub const MAX_ANSWERS_PER_SEED: usize = 64;

impl Kb {
    /// A fresh database with a pool of `size` seeds from `seeds`.
    pub fn with_pool(seeds: impl IntoIterator<Item = u32>) -> Self {
        let mut pool: Vec<u32> = seeds.into_iter().collect();
        pool.sort_unstable();
        pool.dedup();
        Self {
            pool,
            classes: BTreeMap::new(),
        }
    }

    pub fn pool(&self) -> &[u32] {
        &self.pool
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Writes to a temp file next to `path` and renames it over, so a crash
    /// mid-write can't leave a half-written database.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(&tmp, path)
    }

    fn mature(&self, class: &DeviceClass, min_devices: usize) -> Option<&ClassEntry> {
        self.classes
            .get(&class.to_string())
            .map(|(_, e)| e)
            .filter(|e| e.devices.len() >= min_devices)
    }

    /// Records a calibration run. Seeds outside the pool are ignored.
    pub fn calibrate(
        &mut self,
        class: DeviceClass,
        device: &str,
        answers: &[(u32, String)],
    ) -> usize {
        let key = class.to_string();
        let (_, entry) = self
            .classes
            .entry(key)
            .or_insert_with(|| (class, ClassEntry::default()));
        if entry.devices.len() < MAX_DEVICES_PER_CLASS {
            entry.devices.insert(device.to_owned());
        }
        let mut added = 0;
        for (seed, answer) in answers {
            if !self.pool.contains(seed) {
                continue;
            }
            let set = entry.answers.entry(*seed).or_default();
            if set.len() < MAX_ANSWERS_PER_SEED && set.insert(answer.clone()) {
                added += 1;
            }
        }
        added
    }

    /// A seed from the pool that this class has answers for, if the class is
    /// mature; `pick` chooses among them.
    pub fn known_seed(&self, class: &DeviceClass, min_devices: usize, pick: u32) -> Option<u32> {
        let entry = self.mature(class, min_devices)?;
        let seeds: Vec<u32> = entry.answers.keys().copied().collect();
        (!seeds.is_empty()).then(|| seeds[pick as usize % seeds.len()])
    }

    pub fn judge(
        &self,
        class: &DeviceClass,
        seed: u32,
        answer: &str,
        min_devices: usize,
    ) -> Verdict {
        let Some(entry) = self.mature(class, min_devices) else {
            return Verdict::Unknown;
        };
        let Some(answers) = entry.answers.get(&seed) else {
            return Verdict::Unknown;
        };
        if answers.contains(answer) {
            return Verdict::Match;
        }
        let elsewhere = self.classes.values().any(|(c, e)| {
            c != class
                && e.devices.len() >= min_devices
                && e.answers.get(&seed).is_some_and(|a| a.contains(answer))
        });
        if elsewhere {
            Verdict::ClassLie
        } else {
            Verdict::Mismatch
        }
    }

    pub fn summary(&self) -> Vec<(String, usize, usize)> {
        self.classes
            .iter()
            .map(|(k, (_, e))| (k.clone(), e.devices.len(), e.answers.len()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(engine: &str, os: &str) -> DeviceClass {
        DeviceClass {
            engine: engine.into(),
            major: 141,
            os: os.into(),
        }
    }

    fn kb() -> Kb {
        let mut kb = Kb::with_pool([10, 20, 30]);
        let chrome_win = class("blink", "windows");
        let chrome_linux = class("blink", "linux");
        for dev in ["a", "b"] {
            kb.calibrate(
                chrome_win.clone(),
                dev,
                &[(10, "WIN".into()), (20, "WIN20".into())],
            );
        }
        for dev in ["c", "d"] {
            kb.calibrate(chrome_linux.clone(), dev, &[(10, "LINUX".into())]);
        }
        kb
    }

    #[test]
    fn judging() {
        let kb = kb();
        let win = class("blink", "windows");
        assert_eq!(kb.judge(&win, 10, "WIN", 2), Verdict::Match);
        assert_eq!(kb.judge(&win, 10, "NEW", 2), Verdict::Mismatch);
        // a "Windows" browser that renders exactly like Linux Chrome
        assert_eq!(kb.judge(&win, 10, "LINUX", 2), Verdict::ClassLie);
        // not enough devices yet
        assert_eq!(kb.judge(&win, 10, "WIN", 3), Verdict::Unknown);
        // seed nobody calibrated
        assert_eq!(kb.judge(&win, 30, "x", 2), Verdict::Unknown);
        assert_eq!(
            kb.judge(&class("gecko", "windows"), 10, "WIN", 2),
            Verdict::Unknown
        );
    }

    #[test]
    fn known_seed_only_for_mature_classes() {
        let kb = kb();
        let win = class("blink", "windows");
        let s = kb.known_seed(&win, 2, 7).unwrap();
        assert!([10, 20].contains(&s));
        assert_eq!(kb.known_seed(&win, 3, 7), None);
    }

    #[test]
    fn calibration_ignores_seeds_outside_the_pool() {
        let mut kb = Kb::with_pool([1, 2]);
        let added = kb.calibrate(
            class("blink", "windows"),
            "a",
            &[(1, "x".into()), (99, "y".into())],
        );
        assert_eq!(added, 1);
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join(format!("signprint-kb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kb.json");
        let kb = kb();
        kb.save(&path).unwrap();
        let back = Kb::load(&path).unwrap();
        assert_eq!(back.pool(), kb.pool());
        assert_eq!(
            back.judge(&class("blink", "windows"), 10, "WIN", 2),
            Verdict::Match
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
