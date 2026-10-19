//! `runtime/command_activity_display.py` — the local, redacted display text a
//! hook record carries beside its evidence.
//!
//! The preview never leaves the device and never reconstructs shell execution.
//! It renders the command Guard actually checked, strips heredoc bodies,
//! comment tails, secret assignments, URLs, absolute and home paths and email
//! addresses, then hands the remainder to the shared redaction passes.

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use guard_contracts::command_text_from_tool_payload;
use regex::Regex;
use serde_json::{Map, Value};

use crate::cloud_scrub::redact_sensitive_text;
use crate::redacted_command_tokens::redact_text;

/// `INVOCATION_PREVIEW_MAX_CHARS` — characters, as Python counts them.
pub const INVOCATION_PREVIEW_MAX_CHARS: usize = 4_096;

const COMMAND_KEYS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
const INPUT_KEYS: [&str; 4] = ["tool_input", "toolInput", "toolArgs", "arguments"];
const TOOL_NAME_KEYS: [&str; 4] = ["tool_name", "toolName", "name", "tool"];
const REDACTED: &str = "[redacted]";

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").expect("email pattern")
});

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:https?|ssh|git|ftp|ftps|sftp|file)://[^\s"']+"#).expect("url pattern")
});

static POSIX_ABS_PATH_RE: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(r#"(?<![A-Za-z0-9:])(?:"(/[^"]+)"|'(/[^']+)'|(/[^\s"']+))"#)
        .expect("posix path pattern")
});

static WINDOWS_ABS_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:"[A-Za-z]:[\\/][^"]+"|'[A-Za-z]:[\\/][^']+'|[A-Za-z]:[\\/][^\s"']+)"#)
        .expect("windows path pattern")
});

static HOME_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"~[^\s"']*"#).expect("home path pattern"));

static ENV_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*=",
        r#"(?:'(?:\\'|[^'])*'|"(?:\\"|[^"])*"|\S+)"#
    ))
    .expect("environment assignment pattern")
});

static HEREDOC_RE: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(concat!(
        r#"(?s)(?P<op><{2}-?[ \t]*(?P<quote>['"]?)(?P<tag>[^\s'"\\]+)\k<quote>[ \t]*\n)"#,
        r"(?P<body>.*?)(?P<end>\n[ \t]*\k<tag>\b)"
    ))
    .expect("heredoc pattern")
});

/// `checked_command_from_payload` (:33-55) — the command string Guard checked.
pub fn checked_command_from_payload(payload: &Map<String, Value>) -> Option<String> {
    let mut tool_name = first_string(payload, &TOOL_NAME_KEYS);
    let mut tool_input = first_mapping(payload, &INPUT_KEYS);
    if tool_input.is_none_or(Map::is_empty) {
        let (call_name, call_input) =
            tool_call_input(payload.get("toolCalls"), tool_name.as_deref());
        tool_name = tool_name.or(call_name);
        tool_input = call_input;
    }
    if let Some(rendered) = command_text_from_tool_payload(tool_name.as_deref(), tool_input) {
        if !rendered.is_empty() {
            return Some(rendered);
        }
    }
    for key in COMMAND_KEYS {
        if let Some(value) = payload.get(key).and_then(Value::as_str) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

/// `build_invocation_preview` (:58-72) — bounded display text, or `None`.
pub fn build_invocation_preview(
    command_text: Option<&str>,
    home_dir: Option<&str>,
) -> Option<String> {
    let stripped = command_text?.trim();
    if stripped.is_empty() {
        return None;
    }
    // A scrub that could not run leaves no preview at all. The display text is
    // optional; the command it came from is not safe to store unscrubbed.
    let redacted = scrub_residual_private_text(&redact_home_prefix(stripped, home_dir))?;
    let preview = redact_sensitive_text(&redact_text(&redacted).text)
        .trim()
        .to_owned();
    if preview.is_empty() {
        return None;
    }
    if preview.chars().count() > INVOCATION_PREVIEW_MAX_CHARS {
        let kept: String = preview
            .chars()
            .take(INVOCATION_PREVIEW_MAX_CHARS - 1)
            .collect();
        return Some(format!("{kept}…"));
    }
    Some(preview)
}

/// `build_invocation_preview_from_payload` (:75-84).
pub fn build_invocation_preview_from_payload(
    payload: &Map<String, Value>,
    home_dir: Option<&str>,
) -> Option<String> {
    build_invocation_preview(checked_command_from_payload(payload).as_deref(), home_dir)
}

/// `_first_string` (:87-92).
fn first_string(payload: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = payload.get(*key).and_then(Value::as_str) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

/// `_first_mapping` (:95-100).
fn first_mapping<'a>(
    payload: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object))
}

/// `_tool_call_input` (:103-124) — the named call, else the first usable one.
fn tool_call_input<'a>(
    value: Option<&'a Value>,
    expected_tool_name: Option<&str>,
) -> (Option<String>, Option<&'a Map<String, Value>>) {
    let Some(items) = value.and_then(Value::as_array) else {
        return (None, None);
    };
    let mut fallback: Option<(String, Option<&Map<String, Value>>)> = None;
    for item in items {
        let Some(item) = item.as_object() else {
            continue;
        };
        let Some(tool_name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        if tool_name.trim().is_empty() {
            continue;
        }
        let tool_input = item.get("args").and_then(Value::as_object);
        if fallback.is_none() {
            fallback = Some((tool_name.trim().to_owned(), tool_input));
        }
        if expected_tool_name.is_none_or(|expected| expected == tool_name) {
            return (Some(tool_name.trim().to_owned()), tool_input);
        }
    }
    match fallback {
        Some((name, input)) => (Some(name), input),
        None => (None, None),
    }
}

/// `_redact_home_prefix` (:131-137).
fn redact_home_prefix(value: &str, home_dir: Option<&str>) -> String {
    let Some(home) = home_dir else {
        return value.to_owned();
    };
    let home = home.trim_end_matches(['/', '\\']);
    if home.is_empty() {
        return value.to_owned();
    }
    value.replace(home, "~")
}

/// `_scrub_residual_private_text` (:140-148); `None` when a pass could not run.
fn scrub_residual_private_text(value: &str) -> Option<String> {
    let folded = fold_heredoc_bodies(value)?;
    let mut scrubbed = strip_shell_comments(&folded);
    scrubbed = ENV_ASSIGNMENT_RE
        .replace_all(&scrubbed, REDACTED)
        .into_owned();
    scrubbed = URL_RE.replace_all(&scrubbed, REDACTED).into_owned();
    scrubbed = replace_fancy(&POSIX_ABS_PATH_RE, &scrubbed)?;
    scrubbed = WINDOWS_ABS_PATH_RE
        .replace_all(&scrubbed, REDACTED)
        .into_owned();
    scrubbed = HOME_PATH_RE.replace_all(&scrubbed, REDACTED).into_owned();
    scrubbed = EMAIL_RE.replace_all(&scrubbed, REDACTED).into_owned();
    Some(redact_text(&scrubbed).text)
}

/// `_HEREDOC_RE.sub(r"\g<op>…\g<end>", value)` — the body never survives.
fn fold_heredoc_bodies(value: &str) -> Option<String> {
    rewrite(&HEREDOC_RE, value, &["op", "end"], |groups| {
        format!("{}…{}", groups[0], groups[1])
    })
}

/// A whole-match replacement for a lookaround pattern.
fn replace_fancy(pattern: &FancyRegex, value: &str) -> Option<String> {
    rewrite(pattern, value, &[], |_| REDACTED.to_owned())
}

/// Non-overlapping left-to-right substitution, as `re.sub` scans; `None` when
/// the match loop fails.
///
/// The named groups the caller asks for are resolved here rather than handing
/// the match back, because `fancy_regex::Captures` is spelled differently
/// across the versions `guard-command` and `guard-command-build` pin.
fn rewrite(
    pattern: &FancyRegex,
    value: &str,
    groups: &[&str],
    render: impl Fn(&[&str]) -> String,
) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0;
    for captures in pattern.captures_iter(value) {
        let Ok(captures) = captures else {
            // A backtracking bound means the scrub never ran to the end.
            // Python's `re.sub` cannot fail this way, so there is no faithful
            // text to return: the caller drops the preview instead.
            return None;
        };
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let resolved: Vec<&str> = groups
            .iter()
            .map(|name| captures.name(name).map_or("", |group| group.as_str()))
            .collect();
        out.push_str(&value[cursor..whole.start()]);
        out.push_str(&render(&resolved));
        cursor = whole.end();
    }
    out.push_str(&value[cursor..]);
    Some(out)
}

/// `_strip_shell_comments` (:151-188) — hide POSIX-like comment tails.
///
/// This does not reconstruct shell execution. Quoted hashes stay visible, and
/// a backslash-newline survives while the comment after it is removed.
fn strip_shell_comments(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut result: Vec<char> = Vec::with_capacity(chars.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut comment = false;
    for (index, character) in chars.iter().copied().enumerate() {
        if comment {
            if character == '\n' {
                comment = false;
                result.push(character);
            }
            continue;
        }
        if escaped {
            result.push(character);
            escaped = false;
        } else if character == '\\' && quote != Some('\'') {
            result.push(character);
            escaped = true;
        } else if character == '\'' || character == '"' {
            match quote {
                None => quote = Some(character),
                Some(open) if open == character => quote = None,
                Some(_) => {}
            }
            result.push(character);
        } else if character == '#'
            && quote.is_none()
            && (index == 0
                || chars[index - 1].is_whitespace()
                || matches!(chars[index - 1], ';' | '&' | '|' | '(' | ')'))
        {
            while matches!(result.last(), Some(' ' | '\t')) {
                let _ = result.pop();
            }
            comment = true;
        } else {
            result.push(character);
        }
    }
    result.into_iter().collect()
}

#[cfg(test)]
#[path = "hook_evidence_preview_tests.rs"]
mod tests;
