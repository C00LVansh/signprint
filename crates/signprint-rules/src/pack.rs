//! Rule packs: versioned TOML files of weighted rules.
//!
//! ```toml
//! [pack]
//! name = "core"
//! version = "1.0.0"
//! license = "Apache-2.0"
//!
//! [[rule]]
//! id = "core.webdriver"
//! family = "artifact"
//! weight = 60
//! when = "js.webdriver == true"
//! note = "navigator.webdriver is set"
//! ```
//!
//! Tool-specific detection lives in packs rather than in code so it can be
//! updated without a release, and so the public pack and any private ones
//! are just different files.

use serde::Deserialize;

use crate::expr::{Expr, ParseError, Signals};

/// Behaviour rules can only nudge the score, never decide it. A pack that
/// tries to give one more weight than this is refused at load time.
pub const BEHAVIOR_MAX_WEIGHT: i32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Network,
    Artifact,
    Consistency,
    Challenge,
    Behavior,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    pack: PackMeta,
    #[serde(default, rename = "rule")]
    rules: Vec<RuleFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMeta {
    pub name: String,
    pub version: String,
    pub license: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    id: String,
    family: Family,
    weight: i32,
    when: String,
    #[serde(default)]
    note: String,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub family: Family,
    pub weight: i32,
    pub note: String,
    when: Expr,
}

#[derive(Debug, Clone)]
pub struct Pack {
    pub meta: PackMeta,
    pub rules: Vec<Rule>,
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("{0}")]
    Toml(String),
    #[error("rule {id}: {err}")]
    Expr { id: String, err: ParseError },
    #[error("rule {0}: behavior rules are limited to weight ±{BEHAVIOR_MAX_WEIGHT}")]
    BehaviorTooHeavy(String),
    #[error("rule id {0} appears twice")]
    DuplicateId(String),
    #[error("rule {0}: id must start with \"{1}.\"")]
    BadPrefix(String, String),
}

impl Pack {
    pub fn parse(src: &str) -> Result<Self, PackError> {
        let file: PackFile = toml::from_str(src).map_err(|e| PackError::Toml(e.to_string()))?;
        let prefix = format!("{}.", file.pack.name);
        let mut rules: Vec<Rule> = Vec::with_capacity(file.rules.len());
        for r in file.rules {
            if !r.id.starts_with(&prefix) {
                return Err(PackError::BadPrefix(r.id, file.pack.name.clone()));
            }
            if rules.iter().any(|x| x.id == r.id) {
                return Err(PackError::DuplicateId(r.id));
            }
            if r.family == Family::Behavior && r.weight.abs() > BEHAVIOR_MAX_WEIGHT {
                return Err(PackError::BehaviorTooHeavy(r.id));
            }
            let when = Expr::parse(&r.when).map_err(|err| PackError::Expr {
                id: r.id.clone(),
                err,
            })?;
            rules.push(Rule {
                id: r.id,
                family: r.family,
                weight: r.weight,
                note: r.note,
                when,
            });
        }
        Ok(Self {
            meta: file.pack,
            rules,
        })
    }

    /// Every signal any rule in the pack reads. The client only collects these.
    pub fn signals(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in &self.rules {
            for s in r.when.signals() {
                if !out.contains(s) {
                    out.push(s.clone());
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: String,
    pub family: Family,
    pub weight: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Score {
    /// Sum of all non-behaviour weights.
    pub base: i32,
    /// Behaviour weights, already clamped to ±BEHAVIOR_MAX_WEIGHT in total.
    pub behavior: i32,
    pub hits: Vec<Hit>,
}

impl Score {
    pub fn total(&self) -> i32 {
        self.base + self.behavior
    }
}

/// All loaded packs, evaluated together.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    packs: Vec<Pack>,
}

impl RuleSet {
    pub fn new(packs: Vec<Pack>) -> Self {
        Self { packs }
    }

    pub fn packs(&self) -> &[Pack] {
        &self.packs
    }

    pub fn signals(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for p in &self.packs {
            for s in p.signals() {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        out
    }

    pub fn score(&self, signals: &Signals) -> Score {
        let mut s = Score::default();
        for pack in &self.packs {
            for rule in &pack.rules {
                if !rule.when.matches(signals) {
                    continue;
                }
                if rule.family == Family::Behavior {
                    s.behavior += rule.weight;
                } else {
                    s.base += rule.weight;
                }
                s.hits.push(Hit {
                    rule: rule.id.clone(),
                    family: rule.family,
                    weight: rule.weight,
                });
            }
        }
        s.behavior = s.behavior.clamp(-BEHAVIOR_MAX_WEIGHT, BEHAVIOR_MAX_WEIGHT);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::Value;

    const PACK: &str = r#"
        [pack]
        name = "t"
        version = "0.1.0"
        license = "Apache-2.0"

        [[rule]]
        id = "t.webdriver"
        family = "artifact"
        weight = 60
        when = "js.webdriver == true"

        [[rule]]
        id = "t.ua_mismatch"
        family = "consistency"
        weight = 35
        when = "has(worker.ua) && worker.ua != js.ua"

        [[rule]]
        id = "t.moves"
        family = "behavior"
        weight = -10
        when = "beh.moves > 20"

        [[rule]]
        id = "t.moves_more"
        family = "behavior"
        weight = -10
        when = "beh.moves > 50"
    "#;

    fn sig(pairs: &[(&str, Value)]) -> Signals {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn scores_and_clamps_behavior() {
        let set = RuleSet::new(vec![Pack::parse(PACK).unwrap()]);
        let s = set.score(&sig(&[
            ("js.webdriver", Value::Bool(true)),
            ("js.ua", Value::Str("a".into())),
            ("worker.ua", Value::Str("b".into())),
            ("beh.moves", Value::Num(80.0)),
        ]));
        assert_eq!(s.base, 95);
        assert_eq!(s.behavior, -15, "two -10s clamp to -15");
        assert_eq!(s.total(), 80);
        assert_eq!(s.hits.len(), 4);

        let clean = set.score(&Signals::new());
        assert_eq!(clean, Score::default());
    }

    #[test]
    fn lists_signals() {
        let p = Pack::parse(PACK).unwrap();
        assert_eq!(
            p.signals(),
            ["js.webdriver", "worker.ua", "js.ua", "beh.moves"]
        );
    }

    #[test]
    fn refuses_bad_packs() {
        let heavy = PACK.replace(
            "weight = -10\n        when = \"beh.moves > 20\"",
            "weight = -40\n        when = \"beh.moves > 20\"",
        );
        assert!(matches!(
            Pack::parse(&heavy),
            Err(PackError::BehaviorTooHeavy(_))
        ));

        let dup = PACK.replace("t.ua_mismatch", "t.webdriver");
        assert!(matches!(Pack::parse(&dup), Err(PackError::DuplicateId(_))));

        let prefix = PACK.replace("t.webdriver", "other.webdriver");
        assert!(matches!(
            Pack::parse(&prefix),
            Err(PackError::BadPrefix(..))
        ));

        let expr = PACK.replace("js.webdriver == true", "js.webdriver ==");
        assert!(matches!(Pack::parse(&expr), Err(PackError::Expr { .. })));

        assert!(matches!(
            Pack::parse("[pack]\nname = 1"),
            Err(PackError::Toml(_))
        ));
    }
}
