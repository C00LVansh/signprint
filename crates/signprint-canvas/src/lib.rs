//! Server side of the canvas challenge.
//!
//! The browser draws things we choose and reports hashes of what it got back.
//! We never render the challenge ourselves; answers are checked against what
//! calibrated devices of the same class produced. The one exception is the
//! known-answer pattern, simple enough to compute here exactly.

pub mod class;
pub mod kb;
pub mod pattern;
pub mod prng;
