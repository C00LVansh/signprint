//! The parts of signprint that don't care how requests arrive: verifying
//! signed requests, keeping per-session state, and producing the verdict the
//! upstream app sees. The Pingora proxy and any future middleware are thin
//! layers over this.

pub mod network;
pub mod probe;
pub mod store;
pub mod verdict;
pub mod verify;
