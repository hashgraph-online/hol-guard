//! Lexical reading of Guard-managed Cursor hook commands for the
//! `cursor_hook_config` runner-authority kind.
//!
//! Commands are split the way Python's helpers split them: POSIX `shlex` for
//! commands with a single quote (legacy installs) and on POSIX hosts; on
//! Windows a PowerShell `&` call with single-quoted literals, or the Microsoft
//! C runtime rules. An 8.3 short name in a Windows token is mapped back to its
//! long path only from `long_paths`, which Python resolves on the host; every
//! short name met is reported so Python can resolve the ones it has not sent.

use std::collections::{BTreeMap, BTreeSet};

use crate::local_mcp_grant_identity::shlex_split;

pub(crate) const HOOK_SCRIPT_NAME: &str = "hol-guard-cursor-hook.py";
const FROZEN_COMMAND: &str = "__guard-cursor-hook";
const NATIVE_COMMAND: &str = "cursor-hook-bridge";
const FROZEN_LAUNCHERS: &[&str] = &[
    "current-hol-guard",
    "current-hol-guard.cmd",
    "current-hol-guard.exe",
    "hol-guard",
    "hol-guard.exe",
];
const POWERSHELL_BARE_EXCLUDED: &[char] = &[
    '\'', '"', '`', '$', ';', '|', '&', '(', ')', '{', '}', '@', '#', '<', '>', ',',
];
const UNC_PREFIX: &str = "\\\\?\\UNC\\";

/// Python's `str.isspace`.
pub(crate) fn py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

fn separator(ch: char) -> bool {
    ch == ' ' || ch == '\t'
}

/// `[A-Za-z]:[A-Za-z0-9_.~\\-]+`, the shape of an 8.3 Windows path token.
fn is_short_token(token: &str) -> bool {
    let mut chars = token.chars();
    let drive = chars.next().is_some_and(|ch| ch.is_ascii_alphabetic());
    if !drive || chars.next() != Some(':') {
        return false;
    }
    let rest = chars.as_str();
    !rest.is_empty()
        && rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '~' | '\\' | '-'))
}

/// Split with the Microsoft C runtime rules that `python.exe` applies.
fn split_windows(command: &str) -> Option<Vec<String>> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut in_argument = false;
    let mut in_quotes = false;
    let mut backslashes = 0usize;
    for ch in command.chars() {
        if ch == '\\' {
            backslashes += 1;
            in_argument = true;
            continue;
        }
        if ch == '"' {
            current.push_str(&"\\".repeat(backslashes / 2));
            if backslashes % 2 == 1 {
                current.push('"');
            } else {
                in_quotes = !in_quotes;
            }
            backslashes = 0;
            in_argument = true;
            continue;
        }
        current.push_str(&"\\".repeat(backslashes));
        backslashes = 0;
        if separator(ch) && !in_quotes {
            if in_argument {
                arguments.push(std::mem::take(&mut current));
                in_argument = false;
            }
            continue;
        }
        current.push(ch);
        in_argument = true;
    }
    current.push_str(&"\\".repeat(backslashes));
    if in_quotes {
        return None;
    }
    if in_argument {
        arguments.push(current);
    }
    (!arguments.is_empty()).then_some(arguments)
}

/// One PowerShell literal (`'...'`, `''` for a quote) or bare token at `start`.
fn powershell_token(rest: &[char], start: usize) -> Option<(String, usize)> {
    if rest[start] == '\'' {
        let mut value = String::new();
        let mut position = start + 1;
        while position < rest.len() {
            if rest[position] != '\'' {
                value.push(rest[position]);
                position += 1;
            } else if rest.get(position + 1) == Some(&'\'') {
                value.push('\'');
                position += 2;
            } else {
                return Some((value, position + 1));
            }
        }
        // An unclosed literal can only end on a doubled quote, which leaves a
        // quote right after the token: never a complete argument.
        return None;
    }
    let end = rest[start..]
        .iter()
        .position(|ch| py_space(*ch) || POWERSHELL_BARE_EXCLUDED.contains(ch))
        .map_or(rest.len(), |offset| start + offset);
    (end > start).then(|| (rest[start..end].iter().collect(), end))
}

/// Split `& 'program' args` built only from literal and bare tokens.
fn split_powershell(command: &str) -> Option<Vec<String>> {
    let rest: Vec<char> = command.trim_matches(py_space).chars().skip(1).collect();
    let mut arguments = Vec::new();
    let mut position = 0;
    loop {
        while position < rest.len() && separator(rest[position]) {
            position += 1;
        }
        if position == rest.len() {
            break;
        }
        let (value, end) = powershell_token(&rest, position)?;
        if end < rest.len() && !separator(rest[end]) {
            return None;
        }
        arguments.push(value);
        position = end;
    }
    (!arguments.is_empty()).then_some(arguments)
}

/// The part of a Windows path after its drive and root (`ntpath.splitroot`).
fn windows_tail(path: &str) -> &str {
    if let Some(after) = path.strip_prefix('\\') {
        if !after.starts_with('\\') {
            return after;
        }
        let unc = path
            .get(..UNC_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(UNC_PREFIX));
        let start = if unc { UNC_PREFIX.len() } else { 2 };
        let Some(index) = path[start..].find('\\').map(|offset| start + offset) else {
            return "";
        };
        return match path[index + 1..].find('\\') {
            Some(offset) => &path[index + 1 + offset + 1..],
            None => "",
        };
    }
    let mut chars = path.char_indices();
    let first = chars.next();
    match (first, chars.next()) {
        (Some(_), Some((colon, ':'))) => {
            let after = &path[colon + 1..];
            after.strip_prefix('\\').unwrap_or(after)
        }
        _ => path,
    }
}

fn last_part(tail: &str, delimiter: char) -> String {
    tail.split(delimiter)
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or_default()
        .to_string()
}

fn skip_flags(tokens: &[String]) -> &[String] {
    let skip = tokens
        .iter()
        .take_while(|token| token.starts_with('-') && token.as_str() != "-c")
        .count();
    &tokens[skip..]
}

fn client_tokens(tokens: Vec<String>) -> Vec<String> {
    if tokens.len() > 2 && !tokens[0].is_empty() && tokens[1] == NATIVE_COMMAND {
        return tokens[2..].to_vec();
    }
    tokens
}

/// The host command syntax plus the short names Python resolved.
pub(crate) struct Syntax {
    windows: bool,
    long_paths: BTreeMap<String, String>,
    short_tokens: BTreeSet<String>,
}

impl Syntax {
    pub(crate) fn new(windows: bool, long_paths: BTreeMap<String, String>) -> Self {
        Self {
            windows,
            long_paths,
            short_tokens: BTreeSet::new(),
        }
    }

    pub(crate) fn short_tokens(&self) -> &BTreeSet<String> {
        &self.short_tokens
    }

    fn expand(&mut self, token: String) -> String {
        if !token.contains('~') || !is_short_token(&token) {
            return token;
        }
        self.short_tokens.insert(token.clone());
        match self.long_paths.get(&token) {
            Some(long) if !long.is_empty() => long.clone(),
            _ => token,
        }
    }

    /// `split_hook_command_line`.
    fn split_hook(&mut self, command: &str) -> Option<Vec<String>> {
        let leading = command.trim_start_matches(py_space);
        if !self.windows || leading.starts_with('\'') {
            return shlex_split(command);
        }
        if leading.starts_with('&') {
            return split_powershell(command);
        }
        let arguments = split_windows(command)?;
        Some(
            arguments
                .into_iter()
                .map(|token| self.expand(token))
                .collect(),
        )
    }

    /// `split_cursor_hook_command`.
    pub(crate) fn split_cursor(&mut self, command: &str) -> Option<Vec<String>> {
        if command.contains('\'') && !command.trim_start_matches(py_space).starts_with('&') {
            return shlex_split(command);
        }
        self.split_hook(command)
    }

    fn cursor_tokens(&mut self, command: &str) -> Vec<String> {
        self.split_cursor(command).unwrap_or_else(|| {
            command
                .split(py_space)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
    }

    fn client(&mut self, command: &str) -> Vec<String> {
        let tokens = self.cursor_tokens(command);
        client_tokens(tokens)
    }

    /// `hook_token_name`: the final path component of one token.
    fn name(&self, token: &str) -> String {
        if !self.windows {
            return last_part(token, '/');
        }
        let normalized = token.replace('/', "\\");
        last_part(windows_tail(&normalized), '\\')
    }

    fn lower_name(&self, token: &str) -> String {
        self.name(token).to_lowercase()
    }

    /// Whether the client argv inside the native bridge prefix boots the frozen launcher.
    pub(crate) fn boots_frozen(&mut self, command: &str) -> bool {
        let tokens = client_tokens(self.split_cursor(command).unwrap_or_default());
        tokens.len() >= 2 && tokens[1] == FROZEN_COMMAND
    }

    /// `_is_structured_managed_cursor_hook_command`.
    pub(crate) fn is_structured(&mut self, command: &str) -> bool {
        let tokens = self.client(command);
        let Some(first) = tokens.first().map(|token| self.lower_name(token)) else {
            return false;
        };
        if first == HOOK_SCRIPT_NAME {
            return true;
        }
        if tokens.len() >= 3 && tokens[1] == FROZEN_COMMAND {
            return FROZEN_LAUNCHERS.contains(&first.as_str())
                && self.lower_name(&tokens[2]) == HOOK_SCRIPT_NAME;
        }
        if first.starts_with("python") {
            let payload = skip_flags(&tokens[1..]);
            return payload
                .first()
                .is_some_and(|token| self.lower_name(token) == HOOK_SCRIPT_NAME);
        }
        false
    }

    /// The script token `_live_cursor_hook_script_path` would check, before
    /// Python's path checks.
    pub(crate) fn live_script(&mut self, command: &str) -> Option<String> {
        let tokens = self.client(command);
        let first = self.name(tokens.first()?);
        if first == HOOK_SCRIPT_NAME {
            return Some(tokens[0].clone());
        }
        if tokens.len() >= 3 && tokens[1] == FROZEN_COMMAND {
            return Some(tokens[2].clone());
        }
        if first.to_lowercase().starts_with("python") {
            return skip_flags(&tokens[1..])
                .first()
                .filter(|token| token.as_str() != "-c")
                .cloned();
        }
        None
    }

    /// `_is_managed_hook_command` for a string command.
    pub(crate) fn is_managed_command(&mut self, command: &str) -> bool {
        let lowered = command.to_lowercase();
        if lowered.contains("hol-guard-cursor-hook") || lowered.contains(FROZEN_COMMAND) {
            return true;
        }
        if self.is_structured(command) {
            return true;
        }
        if !lowered.replace('-', "_").contains("hol_guard_hook_argv")
            || !lowered.contains("--harness")
            || !lowered.contains("cursor")
        {
            return false;
        }
        let tokens = self.cursor_tokens(command);
        tokens.first().is_some_and(|token| {
            let name = self.name(token);
            name == HOOK_SCRIPT_NAME || name.to_lowercase().starts_with("python")
        })
    }
}
