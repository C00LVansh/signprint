//! Network-layer fingerprints computed by the proxy from raw connection bytes.

pub mod hello;
pub mod ja4;

pub use hello::{ClientHello, Peek};
pub use ja4::{ja4, ja4n};
