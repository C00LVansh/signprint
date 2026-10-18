//! Per-challenge probe program.
//!
//! Each challenge gets its own small JS program generated from `probe_seed`.
//! It has to run in a real DOM to produce the right answer, and we can
//! recompute that answer here from the seed alone, so nothing is stored per
//! challenge. Names and constants change every time, which makes a recorded
//! answer useless for the next challenge.
//!
//! This is deliberately simple for now. It proves "a JS engine with a DOM ran
//! this exact program", not "this is a real browser"; the consistency checks
//! and the canvas challenge handle that part.

/// splitmix64: small, fast, and good enough for picking task parameters.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn ident(&mut self) -> String {
        const FIRST: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const REST: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let len = 5 + self.below(4) as usize;
        let mut s = String::with_capacity(len);
        s.push(FIRST[self.below(26) as usize] as char);
        for _ in 1..len {
            s.push(REST[self.below(36) as usize] as char);
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// JavaScript to serve at `/c/<cid>.js`.
    pub source: String,
    /// Key the answer is reported under.
    pub field: String,
    pub answer: u32,
}

/// Key under which the program registers itself on `self.__signprint`.
pub fn registry_key(challenge_id: &[u8; 16]) -> String {
    challenge_id.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn generate(seed: u64, challenge_id: &[u8; 16]) -> Program {
    let mut rng = Rng(seed);

    let count = 12 + rng.below(13) as usize;
    let values: Vec<u32> = (0..count).map(|_| rng.below(1 << 30) as u32).collect();
    let mult = 3 + 2 * rng.below(1000) as u32; // odd, so the fold doesn't collapse

    // Each new element goes under the current cursor and odd values move the
    // cursor down into it. Every element is appended after everything created
    // before it, so document order is creation order and a text-node walk
    // visits the values in sequence.
    let answer = values
        .iter()
        .fold(0u32, |acc, v| acc.wrapping_mul(mult).wrapping_add(*v));

    let field = rng.ident();
    let [root, cur, arr, i, el, sum, walker, f] = std::array::from_fn(|_| rng.ident());
    let list = values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let key = registry_key(challenge_id);

    let source = format!(
        "(function(){{\
var {f}=function(){{\
var {root}=document.createElement(\"div\"),{cur}={root},{arr}=[{list}];\
for(var {i}=0;{i}<{arr}.length;{i}++){{\
var {el}=document.createElement(\"div\");\
{el}.textContent=String({arr}[{i}]);\
{cur}.appendChild({el});\
if({arr}[{i}]&1){cur}={el};\
}}\
var {sum}=0,{walker}=document.createTreeWalker({root},NodeFilter.SHOW_TEXT);\
while({walker}.nextNode()){sum}=(Math.imul({sum},{mult})+parseInt({walker}.currentNode.data,10))>>>0;\
return {{\"{field}\":{sum}}};\
}};\
(self.__signprint=self.__signprint||{{}})[\"{key}\"]={f};\
}})();\n"
    );

    Program {
        source,
        field,
        answer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_per_seed() {
        let id = [1u8; 16];
        assert_eq!(generate(42, &id), generate(42, &id));
        let a = generate(42, &id);
        let b = generate(43, &id);
        assert_ne!(a.source, b.source);
        assert_ne!(a.field, b.field);
    }

    #[test]
    fn source_registers_under_challenge_id() {
        let p = generate(7, &[0xab; 16]);
        assert!(p.source.contains(&format!("[\"{}\"]", "ab".repeat(16))));
        assert!(p.source.contains(&format!("\"{}\"", p.field)));
    }

    #[test]
    fn answer_matches_manual_fold() {
        // re-derive the parameters the same way generate() does
        let mut rng = Rng(99);
        let count = 12 + rng.below(13) as usize;
        let values: Vec<u32> = (0..count).map(|_| rng.below(1 << 30) as u32).collect();
        let mult = 3 + 2 * rng.below(1000) as u32;
        let mut acc = 0u32;
        for v in values {
            acc = acc.wrapping_mul(mult).wrapping_add(v);
        }
        assert_eq!(generate(99, &[0; 16]).answer, acc);
    }
}
