//! Wire formats shared by the signprint proxy and the browser client.
//!
//! Nothing in here does I/O or picks random numbers. Callers pass nonces and
//! keys in, which keeps every format reproducible from test vectors.

mod error;

pub use error::Error;
