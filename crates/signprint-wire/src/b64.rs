use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::Error;

/// base64url without padding, used for tokens and challenge ids.
pub fn encode_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_url(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::Malformed("base64url"))
}

/// Standard padded base64, which is what structured-field byte sequences use.
pub fn encode_std(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_std(s: &str) -> Result<Vec<u8>, Error> {
    STANDARD.decode(s).map_err(|_| Error::Malformed("base64"))
}
