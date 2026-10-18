//! The expression language rules are written in.
//!
//! It's a small subset of CEL syntax, on purpose:
//!
//! ```text
//! js.engine == "blink" && !has(js.webdriver)
//! contains(lower(http.ua), "headless") || js.languages_len == 0
//! js.hw_concurrency in [1, 2] && worker.platform != js.platform
//! ```
//!
//! No loops, no macros, no user functions, so every expression runs in time
//! linear in its size and the size is capped when the rule loads. Values are
//! null, bool, number (f64), string and list. A signal that wasn't collected is
//! `null`; comparing null with anything except `== null` is false, so a missing
//! signal never makes a rule fire.

use std::collections::HashMap;

pub const MAX_NODES: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<Value>),
}

impl From<&serde_json::Value> for Value {
    fn from(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => n.as_f64().map(Value::Num).unwrap_or(Value::Null),
            serde_json::Value::String(s) => Value::Str(s.clone()),
            serde_json::Value::Array(a) => Value::List(a.iter().map(Value::from).collect()),
            // nested objects aren't part of the signal model
            serde_json::Value::Object(_) => Value::Null,
        }
    }
}

pub type Signals = HashMap<String, Value>;

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Lit(Value),
    Signal(String),
    List(Vec<Node>),
    Not(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Cmp(Op, Box<Node>, Box<Node>),
    Call(Func, Vec<Node>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Func {
    Has,
    Contains,
    StartsWith,
    Lower,
    Size,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("unexpected {found} at {at}")]
    Unexpected { found: String, at: usize },
    #[error("unterminated string at {0}")]
    UnterminatedString(usize),
    #[error("unknown function {0}")]
    UnknownFunction(String),
    #[error("{0} takes {1} argument(s)")]
    Arity(&'static str, usize),
    #[error("has() needs a signal name")]
    HasNeedsSignal,
    #[error("expression too large (more than {MAX_NODES} nodes)")]
    TooLarge,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    Sym(&'static str),
    End,
}

fn lex(src: &str) -> Result<Vec<(Tok, usize)>, ParseError> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
            out.push((Tok::Ident(src[start..i].to_owned()), start));
        } else if c.is_ascii_digit() || (c == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_digit))
        {
            i += 1;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let n = src[start..i].parse().map_err(|_| ParseError::Unexpected {
                found: src[start..i].to_owned(),
                at: start,
            })?;
            out.push((Tok::Num(n), start));
        } else if c == b'"' || c == b'\'' {
            i += 1;
            let mut s = String::new();
            loop {
                match b.get(i) {
                    None => return Err(ParseError::UnterminatedString(start)),
                    Some(&q) if q == c => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') => {
                        match b.get(i + 1) {
                            Some(&e) if e == c || e == b'\\' => s.push(e as char),
                            _ => return Err(ParseError::UnterminatedString(start)),
                        }
                        i += 2;
                    }
                    Some(_) => {
                        let ch = src[i..].chars().next().expect("not at end");
                        s.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            out.push((Tok::Str(s), start));
        } else {
            let two = src.get(i..i + 2).unwrap_or("");
            let sym = match two {
                "&&" | "||" | "==" | "!=" | "<=" | ">=" => {
                    i += 2;
                    ["&&", "||", "==", "!=", "<=", ">="]
                        .into_iter()
                        .find(|s| *s == two)
                        .expect("matched above")
                }
                _ => {
                    i += 1;
                    match c {
                        b'!' => "!",
                        b'<' => "<",
                        b'>' => ">",
                        b'(' => "(",
                        b')' => ")",
                        b'[' => "[",
                        b']' => "]",
                        b',' => ",",
                        _ => {
                            return Err(ParseError::Unexpected {
                                found: (c as char).to_string(),
                                at: start,
                            });
                        }
                    }
                }
            };
            out.push((Tok::Sym(sym), start));
        }
    }
    out.push((Tok::End, src.len()));
    Ok(out)
}

struct Parser {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    nodes: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos].0
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks[self.pos].0.clone();
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn unexpected(&self) -> ParseError {
        let (t, at) = &self.toks[self.pos];
        ParseError::Unexpected {
            found: format!("{t:?}"),
            at: *at,
        }
    }

    fn eat(&mut self, sym: &str) -> bool {
        if matches!(self.peek(), Tok::Sym(s) if *s == sym) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, sym: &str) -> Result<(), ParseError> {
        if self.eat(sym) {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn node(&mut self, n: Node) -> Result<Node, ParseError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(ParseError::TooLarge);
        }
        Ok(n)
    }

    fn or(&mut self) -> Result<Node, ParseError> {
        let mut lhs = self.and()?;
        while self.eat("||") {
            let rhs = self.and()?;
            lhs = self.node(Node::Or(Box::new(lhs), Box::new(rhs)))?;
        }
        Ok(lhs)
    }

    fn and(&mut self) -> Result<Node, ParseError> {
        let mut lhs = self.not()?;
        while self.eat("&&") {
            let rhs = self.not()?;
            lhs = self.node(Node::And(Box::new(lhs), Box::new(rhs)))?;
        }
        Ok(lhs)
    }

    fn not(&mut self) -> Result<Node, ParseError> {
        if self.eat("!") {
            let inner = self.not()?;
            return self.node(Node::Not(Box::new(inner)));
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Node, ParseError> {
        let lhs = self.primary()?;
        let op = match self.peek() {
            Tok::Sym("==") => Op::Eq,
            Tok::Sym("!=") => Op::Ne,
            Tok::Sym("<") => Op::Lt,
            Tok::Sym("<=") => Op::Le,
            Tok::Sym(">") => Op::Gt,
            Tok::Sym(">=") => Op::Ge,
            Tok::Ident(w) if w == "in" => Op::In,
            _ => return Ok(lhs),
        };
        self.bump();
        let rhs = self.primary()?;
        self.node(Node::Cmp(op, Box::new(lhs), Box::new(rhs)))
    }

    fn primary(&mut self) -> Result<Node, ParseError> {
        let n = match self.bump() {
            Tok::Num(n) => Node::Lit(Value::Num(n)),
            Tok::Str(s) => Node::Lit(Value::Str(s)),
            Tok::Sym("(") => {
                let e = self.or()?;
                self.expect(")")?;
                return Ok(e);
            }
            Tok::Sym("[") => {
                let mut items = Vec::new();
                if !self.eat("]") {
                    loop {
                        items.push(self.or()?);
                        if self.eat("]") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                Node::List(items)
            }
            Tok::Ident(w) => match w.as_str() {
                "true" => Node::Lit(Value::Bool(true)),
                "false" => Node::Lit(Value::Bool(false)),
                "null" => Node::Lit(Value::Null),
                _ if matches!(self.peek(), Tok::Sym("(")) => return self.call(w),
                _ => Node::Signal(w),
            },
            _ => {
                self.pos = self.pos.saturating_sub(1);
                return Err(self.unexpected());
            }
        };
        self.node(n)
    }

    fn call(&mut self, name: String) -> Result<Node, ParseError> {
        let (func, arity, label) = match name.as_str() {
            "has" => (Func::Has, 1, "has"),
            "contains" => (Func::Contains, 2, "contains"),
            "starts_with" => (Func::StartsWith, 2, "starts_with"),
            "lower" => (Func::Lower, 1, "lower"),
            "size" => (Func::Size, 1, "size"),
            _ => return Err(ParseError::UnknownFunction(name)),
        };
        self.expect("(")?;
        let mut args = Vec::new();
        if !self.eat(")") {
            loop {
                args.push(self.or()?);
                if self.eat(")") {
                    break;
                }
                self.expect(",")?;
            }
        }
        if args.len() != arity {
            return Err(ParseError::Arity(label, arity));
        }
        if func == Func::Has && !matches!(args[0], Node::Signal(_)) {
            return Err(ParseError::HasNeedsSignal);
        }
        self.node(Node::Call(func, args))
    }
}

/// A parsed, size-checked expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    root: Node,
    signals: Vec<String>,
}

fn collect_signals(n: &Node, out: &mut Vec<String>) {
    match n {
        Node::Signal(s) => {
            if !out.contains(s) {
                out.push(s.clone());
            }
        }
        Node::Lit(_) => {}
        Node::List(xs) | Node::Call(_, xs) => xs.iter().for_each(|x| collect_signals(x, out)),
        Node::Not(a) => collect_signals(a, out),
        Node::And(a, b) | Node::Or(a, b) | Node::Cmp(_, a, b) => {
            collect_signals(a, out);
            collect_signals(b, out);
        }
    }
}

impl Expr {
    pub fn parse(src: &str) -> Result<Self, ParseError> {
        let mut p = Parser {
            toks: lex(src)?,
            pos: 0,
            nodes: 0,
        };
        let root = p.or()?;
        if *p.peek() != Tok::End {
            return Err(p.unexpected());
        }
        let mut signals = Vec::new();
        collect_signals(&root, &mut signals);
        Ok(Self { root, signals })
    }

    /// Signal names this expression reads.
    pub fn signals(&self) -> &[String] {
        &self.signals
    }

    pub fn eval(&self, signals: &Signals) -> Value {
        eval(&self.root, signals)
    }

    /// True only if the expression evaluates to exactly `true`.
    pub fn matches(&self, signals: &Signals) -> bool {
        self.eval(signals) == Value::Bool(true)
    }
}

fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true))
}

fn eval(n: &Node, s: &Signals) -> Value {
    match n {
        Node::Lit(v) => v.clone(),
        Node::Signal(name) => s.get(name).cloned().unwrap_or(Value::Null),
        Node::List(xs) => Value::List(xs.iter().map(|x| eval(x, s)).collect()),
        Node::Not(a) => match eval(a, s) {
            Value::Bool(b) => Value::Bool(!b),
            _ => Value::Null,
        },
        Node::And(a, b) => Value::Bool(truthy(&eval(a, s)) && truthy(&eval(b, s))),
        Node::Or(a, b) => Value::Bool(truthy(&eval(a, s)) || truthy(&eval(b, s))),
        Node::Cmp(op, a, b) => compare(*op, &eval(a, s), &eval(b, s)),
        Node::Call(f, args) => call(*f, args, s),
    }
}

fn compare(op: Op, a: &Value, b: &Value) -> Value {
    use Value::*;
    let r = match (op, a, b) {
        (Op::Eq, Null, Null) => true,
        (Op::Ne, Null, Null) => false,
        // null only equals null; anything else involving null is false
        (Op::Eq, Null, _) | (Op::Eq, _, Null) => false,
        (_, Null, _) | (_, _, Null) => false,
        (Op::Eq, x, y) => x == y,
        (Op::Ne, x, y) => x != y,
        (Op::In, x, List(ys)) => ys.contains(x),
        (Op::In, Str(x), Str(y)) => y.contains(x.as_str()),
        (Op::Lt, Num(x), Num(y)) => x < y,
        (Op::Le, Num(x), Num(y)) => x <= y,
        (Op::Gt, Num(x), Num(y)) => x > y,
        (Op::Ge, Num(x), Num(y)) => x >= y,
        _ => false,
    };
    Bool(r)
}

fn call(f: Func, args: &[Node], s: &Signals) -> Value {
    match f {
        Func::Has => match &args[0] {
            Node::Signal(name) => Value::Bool(!matches!(s.get(name), None | Some(Value::Null))),
            _ => Value::Null,
        },
        Func::Contains | Func::StartsWith => match (eval(&args[0], s), eval(&args[1], s)) {
            (Value::Str(h), Value::Str(n)) => Value::Bool(if f == Func::Contains {
                h.contains(&n)
            } else {
                h.starts_with(&n)
            }),
            (Value::List(h), n) if f == Func::Contains => Value::Bool(h.contains(&n)),
            _ => Value::Null,
        },
        Func::Lower => match eval(&args[0], s) {
            Value::Str(x) => Value::Str(x.to_lowercase()),
            _ => Value::Null,
        },
        Func::Size => match eval(&args[0], s) {
            Value::Str(x) => Value::Num(x.chars().count() as f64),
            Value::List(x) => Value::Num(x.len() as f64),
            _ => Value::Null,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(pairs: &[(&str, Value)]) -> Signals {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn m(src: &str, s: &Signals) -> bool {
        Expr::parse(src)
            .unwrap_or_else(|e| panic!("{src}: {e}"))
            .matches(s)
    }

    #[test]
    fn basics() {
        let s = sig(&[
            ("js.engine", Value::Str("blink".into())),
            ("js.webdriver", Value::Bool(false)),
            ("js.hw", Value::Num(8.0)),
            ("js.ua", Value::Str("Mozilla/5.0 HeadlessChrome/140".into())),
        ]);
        assert!(m(r#"js.engine == "blink""#, &s));
        assert!(m(r#"js.engine != 'gecko' && !js.webdriver"#, &s));
        assert!(m("js.hw >= 4 && js.hw < 64", &s));
        assert!(m("js.hw in [4, 8, 16]", &s));
        assert!(m(r#"contains(lower(js.ua), "headless")"#, &s));
        assert!(m(r#"starts_with(js.ua, "Mozilla/")"#, &s));
        assert!(m("size(js.engine) == 5", &s));
        assert!(m("(false || js.hw == 8) && true", &s));
        assert!(m("has(js.engine) && !has(js.nope)", &s));
    }

    #[test]
    fn missing_signals_never_fire() {
        let s = Signals::new();
        for e in [
            "js.x == true",
            "js.x != true",
            "js.x > 0",
            "js.x < 0",
            r#"contains(js.x, "a")"#,
            "!js.x",
            "js.x in [1, 2]",
        ] {
            assert!(!m(e, &s), "{e} fired on missing signal");
        }
        assert!(m("js.x == null", &s));
        assert!(m("!has(js.x)", &s));
    }

    #[test]
    fn type_mismatches_are_false() {
        let s = sig(&[("a", Value::Str("8".into()))]);
        assert!(!m("a == 8", &s));
        assert!(!m("a > 1", &s));
        assert!(m("a != 8", &s));
    }

    #[test]
    fn reports_signals_used() {
        let e =
            Expr::parse(r#"js.a == 1 && (worker.b != js.a || contains(http.ua, "x"))"#).unwrap();
        assert_eq!(e.signals(), ["js.a", "worker.b", "http.ua"]);
    }

    #[test]
    fn parse_errors() {
        for bad in [
            "js.a ==",
            "js.a == \"open",
            "(js.a",
            "nope(js.a)",
            "has(\"x\")",
            "contains(js.a)",
            "js.a = 1",
            "js.a == 1 js.b",
            "",
        ] {
            assert!(Expr::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn size_cap() {
        let big = vec!["js.a == 1"; 200].join(" || ");
        assert_eq!(Expr::parse(&big), Err(ParseError::TooLarge));
    }

    #[test]
    fn strings_with_escapes_and_unicode() {
        let s = sig(&[("x", Value::Str("it's \"é\"".into()))]);
        assert!(m(r#"x == 'it\'s "é"'"#, &s));
    }
}
