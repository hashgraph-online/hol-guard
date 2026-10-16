//! Alias, function and control-flow body extraction for the GitHub shell
//! classifier (`runtime/github_shell_bindings.py`).

use std::sync::LazyLock;

use regex::Regex;

use crate::hook_adapter_pytext::py_strip;
use crate::sfrs_gh_bindings::{py_pattern, strip_quotes};

static FUNCTION_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py_pattern(
        r"(?:\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(\s*\)\s*)?|\b[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*)(?P<opener>[{(])",
    ))
    .expect("constant pattern")
});

/// `definition_payload`.
pub(crate) fn definition_payload(
    segment: &[String],
    command_name: &str,
    command_index: usize,
) -> String {
    let joined = segment[command_index + 1..].join(" ");
    let payload = py_strip(&joined);
    if command_name == "alias" {
        return match payload.split_once('=') {
            Some((_, body)) => body.to_owned(),
            None => payload.to_owned(),
        };
    }
    for (opener, closer) in [('{', '}'), ('(', ')')] {
        if let Some(opener_index) = payload.find(opener) {
            let rest = &payload[opener_index + 1..];
            let body = rest.rfind(closer).map_or(rest, |at| &rest[..at]);
            return py_strip(body).to_owned();
        }
    }
    let body = payload.rfind('}').map_or(payload, |at| &payload[..at]);
    py_strip(body).to_owned()
}

/// `executable_control_flow_segment`.
pub(crate) fn executable_control_flow_segment(segment: &[String]) -> Vec<String> {
    let mut normalized = segment;
    while let Some(first_token) = normalized.first() {
        let first = strip_quotes(first_token).to_lowercase();
        if first == "coproc" {
            normalized = &normalized[1..];
            if normalized.len() > 1 && (normalized[1] == "(" || normalized[1] == "{") {
                normalized = &normalized[1..];
            }
            continue;
        }
        if matches!(
            first.as_str(),
            "!" | "(" | "{" | "do" | "elif" | "else" | "if" | "then" | "until" | "while"
        ) {
            normalized = &normalized[1..];
            continue;
        }
        if first.ends_with(')') && normalized.len() > 1 {
            normalized = &normalized[1..];
            continue;
        }
        break;
    }
    normalized.to_vec()
}

/// `case_arm_segments`.
pub(crate) fn case_arm_segments(segment: &[String]) -> Vec<Vec<String>> {
    let Some(first) = segment.first() else {
        return Vec::new();
    };
    if strip_quotes(first).to_lowercase() != "case" {
        return Vec::new();
    }
    let mut arms: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for token in segment.iter().skip(3) {
        if matches!(token.as_str(), ";;" | ";&" | ";;&") {
            if !current.is_empty() {
                arms.push(executable_control_flow_segment(&current));
            }
            current.clear();
            continue;
        }
        current.push(token.clone());
    }
    if !current.is_empty() {
        arms.push(executable_control_flow_segment(&current));
    }
    arms.into_iter().filter(|arm| !arm.is_empty()).collect()
}

/// `scoped_command_substitutions`.
pub(crate) fn scoped_command_substitutions(
    command_text: &str,
    payloads: &[String],
) -> Vec<(String, String)> {
    let mut scoped = Vec::new();
    let mut cursor = 0usize;
    for payload in payloads {
        let patterns = [
            format!("$({payload})"),
            format!("<({payload})"),
            format!(">({payload})"),
            format!("`{payload}`"),
        ];
        let position = patterns
            .iter()
            .filter_map(|pattern| command_text[cursor..].find(pattern).map(|at| at + cursor))
            .min();
        let Some(position) = position else {
            continue;
        };
        scoped.push((payload.clone(), command_text[..position].to_owned()));
        cursor = position + 1;
    }
    scoped
}

/// One balanced function body: text, preceding text, byte span of the whole
/// definition.
pub(crate) struct FunctionDefinition {
    pub body: String,
    pub prefix: String,
    pub start: usize,
    pub end: usize,
}

/// `function_definition_payloads`.
pub(crate) fn function_definition_payloads(command_text: &str) -> Vec<FunctionDefinition> {
    let mut payloads = Vec::new();
    for captures in FUNCTION_DEFINITION.captures_iter(command_text) {
        let (Some(whole), Some(opener)) = (captures.get(0), captures.name("opener")) else {
            continue;
        };
        let opener = opener.as_str().chars().next().unwrap_or('{');
        let closer = if opener == '{' { '}' } else { ')' };
        let mut depth = 1usize;
        let mut quote: Option<char> = None;
        let mut escaped = false;
        let mut index = whole.end();
        for (offset, character) in command_text[whole.end()..].char_indices() {
            if depth == 0 {
                break;
            }
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if let Some(open) = quote {
                if character == open {
                    quote = None;
                }
            } else if character == '\'' || character == '"' {
                quote = Some(character);
            } else if character == opener {
                depth += 1;
            } else if character == closer {
                depth -= 1;
            }
            index = whole.end() + offset + character.len_utf8();
        }
        if depth == 0 {
            payloads.push(FunctionDefinition {
                body: command_text[whole.end()..index - 1].to_owned(),
                prefix: command_text[..whole.start()].to_owned(),
                start: whole.start(),
                end: index,
            });
        }
    }
    payloads
}
