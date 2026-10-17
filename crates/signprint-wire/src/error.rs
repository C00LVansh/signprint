#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("input too short")]
    Truncated,
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("sealed object has the wrong kind")]
    WrongKind,
    #[error("sealed for a different host")]
    WrongHost,
    #[error("unknown key id {0}")]
    UnknownKid(u8),
    #[error("authentication failed")]
    BadSeal,
    #[error("content-digest does not match the body")]
    DigestMismatch,
    #[error("malformed {0}")]
    Malformed(&'static str),
}
