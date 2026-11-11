//! The command the YID app shows for a single paused action.
//!
//! The command comes from Guard's stored approval request, the same record the
//! rest of the summary reads, never from the caller. Before it leaves the
//! machine:
//! - the Guard Cloud secret filter replaces tokens, passwords, keys and other
//!   secrets it recognises, run on the whole command before anything is cut,
//!   so a secret is never split past the filter
//! - shell line continuations are joined first, so a secret split across
//!   lines is still one secret to every filter
//! - credentials that filter does not know by name become `[redacted]`: a
//!   user name and password inside a URL (`https://user:pass@host`),
//!   `-u`/`--user` values with a password (`curl -u admin:pw`), password
//!   options (`--pass`, `--pwd`, `--auth`), the `-p` and `-a` passwords of
//!   `mysql`, `sshpass`, `docker login` and `redis-cli`, variables whose name
//!   ends in `PWD`, `PASS` or `AUTH`, and the value of every request header
//!   except a few harmless ones (`Content-Type`, `Accept`, `User-Agent`)
//! - the user's home folder becomes `~`, as does any other user folder under
//!   `/Users`, `/home` or `C:\Users`, wherever a path can start: after a
//!   space, a quote, `=`, a redirect, `@`, `,`, `|`, `;`, `&`, a slash (as in
//!   `file:///Users/...`) or a short flag (`-I/home/...`), so the account name
//!   stays on the machine
//! - control and invisible characters are dropped and the command is cut to
//!   `MAX_COMMAND_CHARS` (in `guard_yanez_pulse::terms`)
//!
//! The row is off by default: the phone shows only the program names unless
//! the user opts in (`pulse_show_command`), after being told what is sent and
//! that this filtering is best-effort, with a YID app approval bound to
//! exactly that settings change.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use guard_command::cloud_scrub::cloud_scrub_text;
use guard_yanez_pulse::terms::command_value;
use regex::{Captures, Regex};
use serde_json::Value;

use crate::approval_gate_pulse_summary::CommandRow;

/// Characters that end a user folder name in a command.
const NAME_END: &str = r#"/\\\s'"`;:|&<>()$,"#;
/// What can come right before a path: the start, any character that cannot
/// be part of a file name, or a short flag such as `-I` or `-L`.
const PATH_LEAD: &str = r"(?P<lead>^|[^A-Za-z0-9._~\-]|-[A-Za-z]{1,2})";
/// One shell word: a quoted string or a run of non-space characters.
const WORD: &str = r#"'[^']*'|"[^"]*"|[^\s'"]+"#;
/// Request headers whose value is never a secret.
const HARMLESS_HEADERS: [&str; 6] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-type",
    "user-agent",
];

/// Whether the YID app shows the command of a single paused action. Off
/// unless the user opted in; only an explicit `true` shows it, so a Guard
/// set up before this setting existed keeps sending program names only.
pub(crate) fn pulse_show_command(state: &Value) -> bool {
    state.get("pulse_show_command") == Some(&Value::Bool(true))
}

/// The command row for a Pulse request, following the user's setting.
pub(crate) fn command_row<'a>(state: &Value, home: Option<&'a str>) -> CommandRow<'a> {
    if pulse_show_command(state) {
        CommandRow::Shown { home }
    } else {
        CommandRow::Hidden
    }
}

/// The command as the YID app shows it, or `None` when nothing is left.
/// `home` is the user's home folder, from the resident's environment.
pub(crate) fn command_preview(command: &str, home: Option<&str>) -> Option<String> {
    if command.trim().is_empty() {
        return None;
    }
    let joined = line_continuations().replace_all(command, "");
    let filtered = cloud_scrub_text(&joined);
    let scrubbed = redact_credentials(&filtered);
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
        r#"{PATH_LEAD}(?:{})(?P<tail>[/\\\s'"`;:|&<>),]|$)"#,
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

/// A backslash at the end of a line, which the shell joins to the next line.
fn line_continuations() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\\r?\n").expect("line continuation pattern"))
}

/// Credentials Guard's secret filter does not know by name, replaced by
/// `[redacted]`. Over-redacting a harmless value is the safe direction.
fn redact_credentials(text: &str) -> String {
    static RULES: OnceLock<Vec<Regex>> = OnceLock::new();
    let rules = RULES.get_or_init(|| {
        [
            // A password option and its value: --pass x, --pwd=x, --auth x.
            format!(r"(?i)(?P<key>--(?:pass|passwd|password|pwd|auth|login-password)(?:=|\s+))(?P<value>{WORD})"),
            // The -p password of sshpass, attached or spaced.
            format!(r"(?i)(?P<key>\bsshpass\b[^;|&\n]*?\s-p\s*)(?P<value>{WORD})"),
            // The attached -pPASSWORD of the MySQL tools; a bare -p prompts.
            format!(r"(?i)(?P<key>\b(?:mysql|mariadb|mysqldump|mysqladmin)\b[^;|&\n]*?\s-p)(?P<value>{WORD})"),
            // The -p password of a registry login.
            format!(r"(?i)(?P<key>\b(?:docker|podman|nerdctl|helm)\s+(?:registry\s+)?login\b[^;|&\n]*?\s-p(?:=|\s+))(?P<value>{WORD})"),
            // The -a password of redis-cli.
            format!(r"(?i)(?P<key>\bredis-cli\b[^;|&\n]*?\s-a\s+)(?P<value>{WORD})"),
            // A variable whose name ends in PWD, PASS or AUTH: MYSQL_PWD=x.
            format!(r"(?P<key>\b[A-Za-z_][A-Za-z0-9_]*(?:PWD|PASS|PASSWD|AUTH|pwd|pass|passwd|auth)=)(?P<value>{WORD})"),
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).expect("credential pattern"))
        .collect()
    });
    let mut current = url_credentials()
        .replace_all(text, "${scheme}[redacted]@")
        .into_owned();
    for rule in rules {
        current = rule
            .replace_all(&current, |c: &Captures| {
                format!("{}{}", &c["key"], redact_word(&c["value"]))
            })
            .into_owned();
    }
    current = user_passwords()
        .replace_all(&current, |c: &Captures| {
            let value = &c["value"];
            if value.contains(':') {
                format!("{}{}", &c["key"], redact_word(value))
            } else {
                c[0].to_owned()
            }
        })
        .into_owned();
    headers()
        .replace_all(&current, |c: &Captures| {
            format!("{}{}", &c["key"], redact_header(&c["value"]))
        })
        .into_owned()
}

/// `[redacted]`, keeping the quotes of a quoted word.
fn redact_word(word: &str) -> String {
    match word.chars().next() {
        Some(quote @ ('\'' | '"')) if word.len() > 1 && word.ends_with(quote) => {
            format!("{quote}[redacted]{quote}")
        }
        _ => "[redacted]".to_owned(),
    }
}

/// A header with its value redacted, unless the header is harmless.
fn redact_header(word: &str) -> String {
    let (open, inner, close) = match word.chars().next() {
        Some(quote @ ('\'' | '"')) if word.len() > 1 && word.ends_with(quote) => (
            &word[..1],
            &word[1..word.len() - 1],
            &word[word.len() - 1..],
        ),
        _ => ("", word, ""),
    };
    match inner.split_once(':') {
        Some((name, _))
            if HARMLESS_HEADERS.contains(&name.trim().to_ascii_lowercase().as_str()) =>
        {
            word.to_owned()
        }
        Some((name, _)) => format!("{open}{name}: [redacted]{close}"),
        None => word.to_owned(),
    }
}

/// `-u`/`--user`/`--proxy-user` and its value; redacted only when the
/// value holds a password (`user:password`).
fn user_passwords() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?P<key>(?:^|\s)(?:-u|--user|--proxy-user|-U)(?:=|\s+)?)(?P<value>{WORD})"
        ))
        .expect("user option pattern")
    })
}

/// `-H`/`--header` and its value.
fn headers() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?P<key>(?:^|\s)(?:-H|--header)(?:=|\s+))(?P<value>{WORD})"
        ))
        .expect("header pattern")
    })
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
            r#"(?i){PATH_LEAD}(?:/Users/|/home/|[a-z]:[\\/]Users[\\/])[^{NAME_END}]+"#
        ))
        .expect("user folder pattern")
    })
}

#[cfg(test)]
#[path = "approval_gate_pulse_command_tests.rs"]
mod tests;
