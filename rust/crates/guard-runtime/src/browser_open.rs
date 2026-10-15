//! `open_browser_url` (`browser_opener.py`): hand a link to the desktop's
//! default browser without waiting for it.
//!
//! Test runs never open a real tab: `PYTEST_CURRENT_TEST` or
//! `HOL_GUARD_TEST_DISABLE_BROWSER_OPEN` suppress the launch unless
//! `HOL_GUARD_TEST_ALLOW_BROWSER_OPEN` opts back in. Linux opens a link only
//! inside a graphical session, through `xdg-open`.

use std::process::{Command, Stdio};

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

/// `_browser_launch_suppressed_for_tests()`.
fn suppressed_for_tests() -> bool {
    if env_flag("HOL_GUARD_TEST_ALLOW_BROWSER_OPEN") {
        return false;
    }
    if std::env::var_os("PYTEST_CURRENT_TEST").is_some_and(|value| !value.is_empty()) {
        return true;
    }
    env_flag("HOL_GUARD_TEST_DISABLE_BROWSER_OPEN")
}

#[cfg(target_os = "macos")]
fn launcher(url: &str) -> Option<Command> {
    let mut command = Command::new("/usr/bin/open");
    command.arg(url);
    Some(command)
}

#[cfg(target_os = "windows")]
fn launcher(url: &str) -> Option<Command> {
    // The URL protocol handler takes the link as one argument, so no shell
    // ever parses it.
    let mut command = Command::new("rundll32.exe");
    command.args(["url.dll,FileProtocolHandler", url]);
    Some(command)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn launcher(url: &str) -> Option<Command> {
    let graphical = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    if !graphical {
        return None;
    }
    let mut command = Command::new("xdg-open");
    command.arg(url);
    Some(command)
}

/// Open `url` and report whether a browser launch was accepted. The
/// launcher is never waited for; it runs detached from the hook's streams.
pub(crate) fn open_browser_url(url: &str) -> bool {
    if suppressed_for_tests() {
        return false;
    }
    let Some(mut command) = launcher(url) else {
        return false;
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}
