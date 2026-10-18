//! Glue between the issuer and the canvas answer database: picks seeds for a
//! challenge, turns the client's answers into `cnv.*` signals for the rules,
//! and takes calibration runs.

use std::path::PathBuf;
use std::sync::RwLock;

use signprint_canvas::class::{self, DeviceClass};
use signprint_canvas::kb::{Kb, Verdict};
use signprint_canvas::pattern;
use signprint_rules::{Signals, Value};

#[derive(Debug, Clone)]
pub struct CanvasConfig {
    pub rounds: u8,
    pub size: u16,
    /// Distinct calibrated devices a class needs before its answers count.
    pub min_devices: usize,
    pub pool_size: usize,
    /// Where the database lives; `None` keeps it in memory only.
    pub kb_path: Option<PathBuf>,
}

impl Default for CanvasConfig {
    fn default() -> Self {
        Self {
            rounds: 3,
            size: 240,
            min_devices: 3,
            pool_size: 32,
            kb_path: None,
        }
    }
}

pub struct Canvas {
    cfg: CanvasConfig,
    kb: RwLock<Kb>,
}

/// What a challenge asks the browser to draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Task {
    pub seed: u32,
    pub rounds: u8,
    pub size: u16,
    pub pattern_seed: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum CanvasError {
    #[error("couldn't read canvas database: {0}")]
    Load(std::io::Error),
    #[error("couldn't save canvas database: {0}")]
    Save(std::io::Error),
    #[error("unrecognised user agent")]
    UnknownClass,
}

/// Pattern seed is derived from the challenge id, so it needs no extra field.
pub fn pattern_seed(challenge_id: &[u8; 16]) -> u32 {
    u32::from_be_bytes(challenge_id[..4].try_into().expect("4 bytes"))
}

impl Canvas {
    /// Loads the database from `cfg.kb_path` if it exists, otherwise starts a
    /// new one with a fresh random seed pool (and writes it out).
    pub fn open(cfg: CanvasConfig, random_seed: impl FnMut() -> u32) -> Result<Self, CanvasError> {
        let kb = match &cfg.kb_path {
            Some(p) if p.exists() => Kb::load(p).map_err(CanvasError::Load)?,
            _ => {
                let kb = Kb::with_pool(std::iter::repeat_with(random_seed).take(cfg.pool_size));
                if let Some(p) = &cfg.kb_path {
                    kb.save(p).map_err(CanvasError::Save)?;
                }
                kb
            }
        };
        Ok(Self {
            cfg,
            kb: RwLock::new(kb),
        })
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Kb> {
        self.kb.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Picks the seed for a challenge. If the claimed class is calibrated we
    /// use one of its known seeds, otherwise any pool seed; `pick` is random.
    pub fn task(&self, claimed_ua: Option<&str>, challenge_id: &[u8; 16], pick: u32) -> Task {
        let kb = self.read();
        let known = claimed_ua
            .and_then(class::claimed)
            .and_then(|c| kb.known_seed(&c, self.cfg.min_devices, pick));
        let pool = kb.pool();
        let seed = known.unwrap_or_else(|| {
            if pool.is_empty() {
                pick
            } else {
                pool[pick as usize % pool.len()]
            }
        });
        Task {
            seed,
            rounds: self.cfg.rounds,
            size: self.cfg.size,
            pattern_seed: pattern_seed(challenge_id),
        }
    }

    /// `cnv.*` signals for an attestation. `ua` is the User-Agent the proxy saw.
    pub fn signals(
        &self,
        ua: Option<&str>,
        seed: u32,
        challenge_id: &[u8; 16],
        answer: Option<&str>,
        pattern_hash: Option<&str>,
    ) -> Signals {
        let mut s = Signals::new();
        s.insert(
            "cnv.present".into(),
            Value::Bool(answer.is_some() && pattern_hash.is_some()),
        );
        if let Some(h) = pattern_hash {
            let exact = h == pattern::expected_hash(pattern_seed(challenge_id));
            s.insert(
                "cnv.noise".into(),
                Value::Str(if exact { "exact" } else { "noise" }.into()),
            );
        }
        if let (Some(answer), Some(class)) = (answer, ua.and_then(class::claimed)) {
            match self
                .read()
                .judge(&class, seed, answer, self.cfg.min_devices)
            {
                Verdict::Unknown => {}
                Verdict::Match => {
                    s.insert("cnv.match".into(), Value::Bool(true));
                }
                Verdict::Mismatch => {
                    s.insert("cnv.match".into(), Value::Bool(false));
                }
                Verdict::ClassLie => {
                    s.insert("cnv.match".into(), Value::Bool(false));
                    s.insert("cnv.class_lie".into(), Value::Bool(true));
                }
            }
        }
        s
    }

    /// Rounds and canvas size every task uses; calibration has to match.
    pub fn shape(&self) -> (u8, u16) {
        (self.cfg.rounds, self.cfg.size)
    }

    pub fn pool(&self) -> Vec<u32> {
        self.read().pool().to_vec()
    }

    /// Adds a calibration run for the class `ua` claims, and saves.
    pub fn calibrate(
        &self,
        ua: &str,
        device: &str,
        answers: &[(u32, String)],
    ) -> Result<(DeviceClass, usize), CanvasError> {
        let class = class::claimed(ua).ok_or(CanvasError::UnknownClass)?;
        let mut kb = self.kb.write().unwrap_or_else(|p| p.into_inner());
        let added = kb.calibrate(class.clone(), device, answers);
        if let Some(p) = &self.cfg.kb_path {
            kb.save(p).map_err(CanvasError::Save)?;
        }
        Ok((class, added))
    }

    pub fn summary(&self) -> Vec<(String, usize, usize)> {
        self.read().summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
    const LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

    fn canvas() -> Canvas {
        let mut n = 0;
        Canvas::open(
            CanvasConfig {
                min_devices: 2,
                pool_size: 4,
                ..CanvasConfig::default()
            },
            || {
                n += 1;
                n * 100
            },
        )
        .unwrap()
    }

    #[test]
    fn signals_from_answers() {
        let c = canvas();
        for dev in ["a", "b"] {
            c.calibrate(WIN, dev, &[(100, "W".into())]).unwrap();
            c.calibrate(LINUX, &format!("l{dev}"), &[(100, "L".into())])
                .unwrap();
        }
        let id = [7u8; 16];
        let good_pattern = pattern::expected_hash(pattern_seed(&id));

        let s = c.signals(Some(WIN), 100, &id, Some("W"), Some(&good_pattern));
        assert_eq!(s.get("cnv.match"), Some(&Value::Bool(true)));
        assert_eq!(s.get("cnv.noise"), Some(&Value::Str("exact".into())));

        // claims Windows, renders like Linux
        let s = c.signals(Some(WIN), 100, &id, Some("L"), Some(&good_pattern));
        assert_eq!(s.get("cnv.class_lie"), Some(&Value::Bool(true)));

        let s = c.signals(Some(WIN), 100, &id, Some("W"), Some("not the right hash"));
        assert_eq!(s.get("cnv.noise"), Some(&Value::Str("noise".into())));

        let s = c.signals(Some(WIN), 100, &id, None, None);
        assert_eq!(s.get("cnv.present"), Some(&Value::Bool(false)));
        assert!(!s.contains_key("cnv.match"));
    }

    #[test]
    fn tasks_prefer_calibrated_seeds() {
        let c = canvas();
        assert_eq!(c.pool(), [100, 200, 300, 400]);
        for dev in ["a", "b"] {
            c.calibrate(WIN, dev, &[(300, "W".into())]).unwrap();
        }
        for pick in 0..10 {
            assert_eq!(c.task(Some(WIN), &[0; 16], pick).seed, 300);
        }
        // uncalibrated class: any pool seed
        assert!(c.pool().contains(&c.task(Some(LINUX), &[0; 16], 5).seed));
        assert!(matches!(
            c.calibrate("curl/8", "x", &[]),
            Err(CanvasError::UnknownClass)
        ));
    }
}
