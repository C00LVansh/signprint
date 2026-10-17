//! Wire formats shared by the signprint proxy and the browser client.
//!
//! Nothing in here does I/O or picks random numbers. Callers pass nonces and
//! keys in, which keeps every format reproducible from test vectors.

pub mod b64;
pub mod bind;
pub mod challenge;
pub mod keys;
pub mod nonce;
pub mod replay;
pub mod seal;
pub mod token;

mod error;

pub use error::Error;
