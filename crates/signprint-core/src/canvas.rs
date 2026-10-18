//! Glue between the issuer and the canvas answer database: picks seeds for a
//! challenge, turns the client's answers into `cnv.*` signals for the rules,
//! and takes calibration runs.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

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
    seen: Mutex<Seen>,
}

/// Which engine/OS combinations reported each (seed, answer) recently. Real
/// devices on different engines or OSes don't produce identical renders, so
/// one answer turning up under several of them is a replay or an emulator.
/// Memory only, bounded, and cleared wholesale when it fills up.
#[derive(Default)]
struct Seen {
    map: HashMap<(u32, String), BTreeSet<(String, String)>>,
}

const SEEN_MAX_KEYS: usize = 100_000;
const SEEN_MAX_PLATFORMS: usize = 16;

impl Seen {
    fn record(&mut self, seed: u32, answer: &str, class: &DeviceClass) -> usize {
        if self.map.len() >= SEEN_MAX_KEYS {
            self.map.clear();
        }
        let set = self.map.entry((seed, answer.to_owned())).or_default();
        if set.len() < SEEN_MAX_PLATFORMS {
            set.insert((class.engine.clone(), class.os.clone()));
        }
        set.len()
    }
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
            seen: Mutex::default(),
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

    /// `cnv.gl_*` signals: the WebGL answer judged against the GPU the browser
    /// reports. No shared-answer counting here: several browsers on one
    /// machine legitimately agree on WebGL.
    pub fn webgl_signals(
        &self,
        renderer: Option<&str>,
        seed: u32,
        answer: Option<&str>,
    ) -> Signals {
        let mut s = Signals::new();
        s.insert("cnv.gl_present".into(), Value::Bool(answer.is_some()));
        if let (Some(answer), Some(renderer)) = (answer, renderer) {
            match self
                .read()
                .judge_gpu(renderer, seed, answer, self.cfg.min_devices)
            {
                Verdict::Unknown => {}
                Verdict::Match => {
                    s.insert("cnv.gl_match".into(), Value::Bool(true));
                }
                Verdict::Mismatch => {
                    s.insert("cnv.gl_match".into(), Value::Bool(false));
                }
                Verdict::ClassLie => {
                    s.insert("cnv.gl_match".into(), Value::Bool(false));
                    s.insert("cnv.gl_class_lie".into(), Value::Bool(true));
                }
            }
        }
        s
    }

    /// Adds WebGL calibration answers for the GPU a device reports, and saves.
    pub fn calibrate_gpu(
        &self,
        renderer: &str,
        device: &str,
        answers: &[(u32, String)],
    ) -> Result<usize, CanvasError> {
        let mut kb = self.kb.write().unwrap_or_else(|p| p.into_inner());
        let added = kb.calibrate_gpu(renderer, device, answers);
        if let Some(p) = &self.cfg.kb_path {
            kb.save(p).map_err(CanvasError::Save)?;
        }
        Ok(added)
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
            let platforms = self
                .seen
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .record(seed, answer, &class);
            s.insert("cnv.shared_platforms".into(), Value::Num(platforms as f64));
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
    fn one_answer_under_many_platforms_is_counted() {
        let c = canvas();
        let id = [1u8; 16];
        let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15";
        let shared = |s: &Signals| s.get("cnv.shared_platforms").cloned();

        assert_eq!(
            shared(&c.signals(Some(WIN), 9, &id, Some("SAME"), None)),
            Some(Value::Num(1.0))
        );
        // the same device again doesn't add anything
        assert_eq!(
            shared(&c.signals(Some(WIN), 9, &id, Some("SAME"), None)),
            Some(Value::Num(1.0))
        );
        assert_eq!(
            shared(&c.signals(Some(LINUX), 9, &id, Some("SAME"), None)),
            Some(Value::Num(2.0))
        );
        assert_eq!(
            shared(&c.signals(Some(mac), 9, &id, Some("SAME"), None)),
            Some(Value::Num(3.0))
        );
        // a different answer is counted separately
        assert_eq!(
            shared(&c.signals(Some(mac), 9, &id, Some("OTHER"), None)),
            Some(Value::Num(1.0))
        );
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
