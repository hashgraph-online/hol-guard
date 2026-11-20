//! The bounded `--version` probe and the banner shape it accepts, split
//! from the discovery module.

use std::io::Read;
use std::process::Command;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;

use super::{parse_version, Version, VersionSource, MAX_BANNER_BYTES, PROBE_TIMEOUT};

pub(super) enum Probe {
    /// Exit status 0, with at most `MAX_BANNER_BYTES + 1` bytes of stdout.
    Exited(Vec<u8>),
    Failed,
    TimedOut,
}

/// Run `command` for at most `PROBE_TIMEOUT`, killing it on the deadline.
pub(super) fn run_bounded(mut command: Command) -> Probe {
    let Ok(mut child) = command.spawn() else {
        return Probe::Failed;
    };
    // The reader hands its bytes over a channel so a grandchild that keeps
    // stdout open cannot hold the probe past its deadline.
    let (sender, receiver) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout
                .take(MAX_BANNER_BYTES as u64 + 1)
                .read_to_end(&mut bytes);
            let _ = sender.send(bytes);
        });
    }
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => break None,
        }
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return Probe::TimedOut;
    };
    if !status.success() {
        return Probe::Failed;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(stdout) => Probe::Exited(stdout),
        Err(mpsc::RecvTimeoutError::Timeout) => Probe::TimedOut,
        Err(mpsc::RecvTimeoutError::Disconnected) => Probe::Failed,
    }
}

/// A `--version` banner in the harness's known shape only: one non-empty
/// line holding exactly one version, after a known prefix and before nothing.
pub(super) fn parse_banner(source: &VersionSource, banner: &str) -> Option<Version> {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let token = TOKEN.get_or_init(|| {
        Regex::new(r"(?:^|[^0-9])(v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)")
            .expect("banner pattern compiles")
    });
    if banner.len() > MAX_BANNER_BYTES {
        return None;
    }
    let lines: Vec<&str> = banner
        .split(is_line_break)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let [line] = lines.as_slice() else {
        return None;
    };
    let tokens = banner_tokens(token, line);
    let [found] = tokens.as_slice() else {
        return None;
    };
    let start = line.find(found)?;
    let prefix = line[..start]
        .trim()
        .trim_end_matches([':', '/'])
        .trim()
        .to_lowercase();
    let suffix = line[start + found.len()..].trim();
    if !source.banner_prefixes.contains(&prefix.as_str()) || !suffix.is_empty() {
        return None;
    }
    parse_version(found)
}

/// The separators Python's `str.splitlines` breaks on.
fn is_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Non-overlapping version tokens, each not preceded by a digit.
fn banner_tokens<'a>(token: &Regex, line: &'a str) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut offset = 0;
    while let Some(captures) = token.captures(&line[offset..]) {
        let Some(matched) = captures.get(1) else {
            break;
        };
        found.push(&line[offset + matched.start()..offset + matched.end()]);
        offset += matched.end();
    }
    found
}
