//! Device class: the coarse bucket a canvas answer is expected to be stable
//! within. As in the Picasso paper this is browser engine, major version and
//! OS family. Hardware isn't in the user agent, so GPU differences show up as
//! several valid answers per class rather than separate classes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceClass {
    pub engine: String,
    pub major: u32,
    pub os: String,
}

impl std::fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.engine, self.major, self.os)
    }
}

fn version_after(ua: &str, marker: &str) -> Option<u32> {
    let rest = &ua[ua.find(marker)? + marker.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn os_family(ua: &str) -> &'static str {
    // order matters: iPhone UAs mention "Mac OS X", Android ones mention Linux
    if ua.contains("iPhone") || ua.contains("iPad") {
        "ios"
    } else if ua.contains("Android") {
        "android"
    } else if ua.contains("Windows") {
        "windows"
    } else if ua.contains("CrOS") {
        "chromeos"
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        "macos"
    } else if ua.contains("Linux") {
        "linux"
    } else {
        "other"
    }
}

/// The class a user agent claims. `None` for anything we can't place.
pub fn claimed(ua: &str) -> Option<DeviceClass> {
    let os = os_family(ua).to_owned();
    // Edge, Opera, Brave etc. are Chromium and render like it
    let (engine, major) = if let Some(v) = version_after(ua, "Firefox/") {
        ("gecko", v)
    } else if let Some(v) = version_after(ua, "Chrome/").or_else(|| version_after(ua, "CriOS/")) {
        // Chrome on iOS is WebKit underneath
        (if os == "ios" { "webkit" } else { "blink" }, v)
    } else if ua.contains("Safari/") {
        ("webkit", version_after(ua, "Version/")?)
    } else {
        return None;
    };
    Some(DeviceClass {
        engine: engine.to_owned(),
        major,
        os,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(ua: &str) -> String {
        claimed(ua).map(|c| c.to_string()).unwrap_or_default()
    }

    #[test]
    fn common_user_agents() {
        assert_eq!(
            c(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
            ),
            "blink/141/windows"
        );
        assert_eq!(
            c(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0"
            ),
            "gecko/144/macos"
        );
        assert_eq!(
            c(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"
            ),
            "webkit/18/macos"
        );
        assert_eq!(
            c(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0 Mobile/15E148 Safari/604.1"
            ),
            "webkit/141/ios"
        );
        assert_eq!(
            c(
                "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36"
            ),
            "blink/141/android"
        );
        assert_eq!(
            c(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
            ),
            "blink/141/linux"
        );
        assert_eq!(c("curl/8.10.1"), "");
    }
}
