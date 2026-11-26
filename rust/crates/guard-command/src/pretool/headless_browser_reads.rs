//! A headless browser that prints one local page and exits.
//!
//! `chromium --headless=new --user-data-dir=/tmp/run --dump-dom
//! http://127.0.0.1:3000` starts a browser with no window, loads the page a
//! developer is serving on this machine, prints its DOM to standard output and
//! exits. It is how a session checks what a dev server renders. An unknown
//! executable is otherwise held for review, so this screen proves the one
//! launch shape that carries no browser risk.
//!
//! The browser risk is in the profile and the control channel, and the screen
//! closes both:
//!
//! - The profile has to be a named directory under `/tmp`. A browser's own
//!   profile, which holds the user's signed-in sessions, saved passwords and
//!   cookies, never lives there, so the page loads with no session.
//! - Every word has to be on a short list. A remote debugging port or pipe,
//!   `--profile-directory`, an extension, a proxy, `--no-sandbox` or any
//!   other switch refuses the whole line. Chromium also reads a switch spelled
//!   with one dash, and an unrecognised word is refused for the same reason.
//!
//! The target has to be one loopback `http` or `https` address, with an
//! optional port and a plain path. A word with `@` or `\` in it is refused, so
//! an address cannot smuggle another host in as user information.
//!
//! The browser must print rather than write: `--dump-dom` is required, and
//! `--screenshot` and `--print-to-pdf`, which write a file, are not admitted.
//! A Chromium switch takes its value after `=` only; a value in the next word
//! would be read as another address, so the value-taking switches are read in
//! that one spelling.

/// The Chromium-family executables this screen reads.
const BROWSERS: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
    "microsoft-edge",
    "microsoft-edge-stable",
];

/// Switches that change nothing about the profile, the network or the files
/// the browser writes.
const INERT_SWITCHES: &[&str] = &[
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--hide-scrollbars",
    "--mute-audio",
];

/// A headless `--dump-dom` of one loopback page on a temporary profile.
pub(super) fn safe_headless_browser_read(basename: &str, arguments: &[String]) -> bool {
    if !BROWSERS.contains(&basename) {
        return false;
    }
    let mut headless = false;
    let mut dump_dom = false;
    let mut profiles = 0;
    let mut targets = 0;
    for argument in arguments {
        let word = argument.as_str();
        let accepted = match word {
            "--headless" | "--headless=new" | "--headless=old" => {
                headless = true;
                true
            }
            "--dump-dom" => {
                dump_dom = true;
                true
            }
            _ if INERT_SWITCHES.contains(&word) => true,
            _ => {
                if let Some(directory) = word.strip_prefix("--user-data-dir=") {
                    profiles += 1;
                    temporary_profile(directory)
                } else if let Some(size) = word.strip_prefix("--window-size=") {
                    window_size(size)
                } else if let Some(value) = word
                    .strip_prefix("--virtual-time-budget=")
                    .or_else(|| word.strip_prefix("--timeout="))
                {
                    plain_number(value)
                } else {
                    targets += 1;
                    loopback_address(word)
                }
            }
        };
        if !accepted {
            return false;
        }
    }
    headless && dump_dom && profiles == 1 && targets == 1
}

/// A named directory under the shared temporary directory.
fn temporary_profile(directory: &str) -> bool {
    let Some(rest) = directory
        .strip_prefix("/tmp/")
        .or_else(|| directory.strip_prefix("/private/tmp/"))
    else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    !rest.is_empty()
        && rest.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// `WIDTH,HEIGHT` in pixels.
fn window_size(value: &str) -> bool {
    matches!(value.split_once(','), Some((width, height)) if plain_number(width) && plain_number(height))
}

/// A plain number of at most six digits.
fn plain_number(value: &str) -> bool {
    (1..=6).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// One `http` or `https` address on this host, with an optional port and a
/// path made of ordinary URL characters.
fn loopback_address(word: &str) -> bool {
    let Some(rest) = word
        .strip_prefix("http://")
        .or_else(|| word.strip_prefix("https://"))
    else {
        return false;
    };
    let host_end = if rest.starts_with('[') {
        rest.find(']').map(|index| index + 1)
    } else {
        Some(rest.find([':', '/']).unwrap_or(rest.len()))
    };
    let Some(host_end) = host_end else {
        return false;
    };
    let (host, rest) = rest.split_at(host_end);
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return false;
    }
    let path = match rest.strip_prefix(':') {
        Some(port_and_path) => {
            let port_end = port_and_path.find('/').unwrap_or(port_and_path.len());
            let (port, path) = port_and_path.split_at(port_end);
            if !(1..=5).contains(&port.len()) || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            path
        }
        None => rest,
    };
    (path.is_empty() || path.starts_with('/'))
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/-._~%?=&#+,".contains(&byte))
}

#[cfg(test)]
#[path = "headless_browser_reads_tests.rs"]
mod tests;
