//! The command the YID app shows for a single paused action.
//!
//! The command comes from Guard's stored approval request, the same record the
//! rest of the summary reads, never from the caller. Before it leaves the
//! machine:
//! - the Guard Cloud secret filter replaces tokens, passwords, keys and other
//!   secrets it recognises, run on the whole command before anything is cut,
//!   so a secret is never split past the filter
//! - a user name and password inside a URL (`https://user:pass@host`), which
//!   that filter leaves alone, become `[redacted]`
//! - the user's home folder becomes `~`, as does any other user folder under
//!   `/Users`, `/home` or `C:\Users`, so the account name stays on the machine
//! - control and invisible characters are dropped and the command is cut to
//!   `MAX_COMMAND_CHARS` (in `guard_yanez_pulse::terms`)
//!
//! The user can turn this row off (`pulse_show_command`); the phone then shows
//! only the program names, as before.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use guard_command::cloud_scrub::cloud_scrub_text;
use guard_yanez_pulse::terms::command_value;
use regex::Regex;

/// Characters that end a user folder name in a command.
const NAME_END: &str = r#"/\\\s'"`;:|&<>()$"#;

/// The command as the YID app shows it, or `None` when nothing is left.
/// `home` is the user's home folder, from the resident's environment.
pub(crate) fn command_preview(command: &str, home: Option<&str>) -> Option<String> {
    if command.trim().is_empty() {
        return None;
    }
    let filtered = cloud_scrub_text(command);
    let scrubbed = url_credentials()
        .replace_all(&filtered, "${scheme}[redacted]@")
        .into_owned();
    let homed = match home.filter(|home| usable_home(home)) {
        Some(home) => replace_home(&scrubbed, home),
        None => scrubbed,
    };
    let anonymous = user_folders().replace_all(&homed, "${lead}~");
    command_value(&anonymous)
}

/// The resident's home folder: `HOME`, or `USERPROFILE` on Windows.
pub(crate) fn current_home() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .filter(|home| usable_home(home))
}

/// A home folder that names a real folder, not `/` or an empty value.
fn usable_home(home: &str) -> bool {
    let trimmed = home.trim_end_matches(['/', '\\']);
    trimmed.len() > 1 && !trimmed.ends_with(':')
}

/// Every whole-path use of `home` becomes `~`. A longer name that only starts
/// with it, such as `/home/omar2` for `/home/omar`, is left alone.
fn replace_home(text: &str, home: &str) -> String {
    let home = home.trim_end_matches(['/', '\\']);
    let pattern = format!(
        r#"(?P<lead>^|[\s'"`=:(])(?:{})(?P<tail>[/\\\s'"`;:|&<>)]|$)"#,
        regex::escape(home)
    );
    match Regex::new(&pattern) {
        Ok(re) => {
            // Run until nothing changes: adjacent matches share a boundary.
            let mut current = text.to_owned();
            loop {
                let next = re.replace_all(&current, "${lead}~${tail}").into_owned();
                if next == current {
                    return current;
                }
                current = next;
            }
        }
        Err(_) => text.to_owned(),
    }
}

/// `scheme://user:password@` in a URL.
fn url_credentials() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?P<scheme>\b[a-z][a-z0-9+.-]*://)[^/\s@'"]+@"#)
            .expect("url credential pattern")
    })
}

/// `/Users/<name>`, `/home/<name>` and `C:\Users\<name>` at the start of a
/// path, for any account name.
fn user_folders() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<lead>^|[\s'"`=:(])(?:/Users/|/home/|[a-z]:[\\/]Users[\\/])[^{NAME_END}]+"#
        ))
        .expect("user folder pattern")
    })
}

#[cfg(test)]
#[path = "approval_gate_pulse_command_tests.rs"]
mod tests;
