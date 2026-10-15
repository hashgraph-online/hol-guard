//! Pipeline splitting, token rewriting and output filters for Actions reads
//! (`github_actions_read_workflow.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::github_capability_contract::GitHubCommandCapability;
use crate::github_capability_interaction::github_capability_requires_confirmation;
use crate::github_command_capabilities::classify_github_cli;
use crate::sfrs_gh_pyshim::decimal_digits_value;
use crate::sfrs_shlex::{split_with, PIPE_LEXER};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ValueKind {
    Number,
    Text,
}

pub(crate) const NAME: &str = "[A-Za-z_][A-Za-z0-9_]*";
const REPOSITORY_PART: &str = "[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})";
const MAX_FILTER_LINES: u64 = 100;
const MAX_FAILED_LOG_TAIL_LINES: u64 = 120;
const LOG_METADATA_FIELDS: &[&str] = &[
    "UV_PYTHON_INSTALL_DIR",
    "toolcache",
    "pythonLoc",
    "hostedtoolcache",
];

pub(crate) static VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\$(?:\{{(?P<braced>{NAME})\}}|(?P<plain>{NAME}))"
    ))
    .expect("variable")
});
pub(crate) static REPOSITORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\A{REPOSITORY_PART}/{REPOSITORY_PART}\z")).expect("repository")
});
static ACTIONS_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\Arepos/{REPOSITORY_PART}/{REPOSITORY_PART}/actions/(?:runs/[1-9][0-9]*/jobs|jobs/[1-9][0-9]*(?:/logs)?)\z"
    ))
    .expect("endpoint")
});
static JOB_ID_QUERY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A\.jobs\[\]\.id\z").expect("job id"));
static FILTERED_JOB_ID_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\A\.jobs\[\]\|select\(\.name\|test\("(?:[^"\\]|\\.){1,200}"\)\)\|\.id\z"#)
        .expect("filtered job id")
});
static POSITIVE_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[1-9][0-9]*\z").expect("number"));
static JSON_FIELDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[A-Za-z][A-Za-z0-9_,]*\z").expect("json fields"));

pub(crate) fn is_positive_number(text: &str) -> bool {
    POSITIVE_NUMBER.is_match(text)
}

pub(crate) fn is_repository(text: &str) -> bool {
    REPOSITORY.is_match(text)
}

/// `_pipeline_segments`: an empty result is the rejection.
pub(crate) fn pipeline_segments(command_text: &str) -> Vec<Vec<String>> {
    let Ok(tokens) = split_with(PIPE_LEXER, command_text) else {
        return Vec::new();
    };
    let mut segments: Vec<Vec<String>> = vec![Vec::new()];
    for token in tokens {
        if token != "|" {
            segments.last_mut().expect("segment").push(token);
            continue;
        }
        if segments.last().expect("segment").is_empty() {
            return Vec::new();
        }
        segments.push(Vec::new());
    }
    if segments.last().expect("segment").is_empty() {
        Vec::new()
    } else {
        segments
    }
}

fn variable_name<'a>(captures: &'a Captures<'_>) -> Option<&'a str> {
    // Python `braced or plain`: both names are non-empty when present.
    captures
        .name("braced")
        .or_else(|| captures.name("plain"))
        .map(|found| found.as_str())
}

/// `_substitute_number_variables`.
pub(crate) fn substitute_number_variables(
    tokens: &[String],
    values: &HashMap<String, ValueKind>,
) -> Option<Vec<String>> {
    let mut substituted = Vec::new();
    for token in tokens {
        let mut unknown = false;
        let value = VARIABLE.replace_all(token, |captures: &Captures<'_>| {
            match variable_name(captures) {
                Some(name) if values.get(name) == Some(&ValueKind::Number) => "1",
                _ => {
                    unknown = true;
                    ""
                }
            }
        });
        if unknown || value.contains('$') {
            return None;
        }
        substituted.push(value.into_owned());
    }
    Some(substituted)
}

/// `_without_safe_stderr_redirect`.
pub(crate) fn without_safe_stderr_redirect(tokens: &[String]) -> Option<Vec<String>> {
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "2>/dev/null" || token == "2>&1" {
            index += 1;
            continue;
        }
        if token == "2>" && index + 1 < tokens.len() && tokens[index + 1] == "/dev/null" {
            index += 2;
            continue;
        }
        if token.contains('>') || token.contains('<') {
            return None;
        }
        filtered.push(token.clone());
        index += 1;
    }
    Some(filtered)
}

/// `_safe_actions_github_command`.
pub(crate) fn safe_actions_github_command(tokens: &[String]) -> bool {
    if tokens.len() < 3 || tokens[0] != "gh" {
        return false;
    }
    let assessment = classify_github_cli(&tokens[1..]);
    if assessment.capability != GitHubCommandCapability::ReadRemote
        || github_capability_requires_confirmation(&assessment)
    {
        return false;
    }
    if tokens[1] == "run" && tokens[2] == "view" {
        return safe_run_view_args(&tokens[3..]);
    }
    if tokens[1] != "api" || tokens[2].starts_with('-') {
        return false;
    }
    ACTIONS_ENDPOINT.is_match(&tokens[2]) && safe_api_options(&tokens[3..])
}

/// `_safe_run_view_args`.
pub(crate) fn safe_run_view_args(args: &[String]) -> bool {
    if args.is_empty() || !is_positive_number(&args[0]) {
        return false;
    }
    let mut index = 1;
    let mut saw_repository = false;
    while index < args.len() {
        let option = args[index].as_str();
        if !matches!(option, "--repo" | "--json" | "--jq") || index + 1 >= args.len() {
            return false;
        }
        let value = &args[index + 1];
        if option == "--repo" {
            if saw_repository || !is_repository(value) {
                return false;
            }
            saw_repository = true;
        }
        if option == "--json" && !JSON_FIELDS.is_match(value) {
            return false;
        }
        index += 2;
    }
    saw_repository
}

/// `_safe_api_options`.
pub(crate) fn safe_api_options(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        if args[index] != "--jq" || index + 1 >= args.len() {
            return false;
        }
        index += 2;
    }
    true
}

/// `_github_output_kind`.
pub(crate) fn github_output_kind(tokens: &[String]) -> ValueKind {
    for (index, token) in tokens.iter().enumerate() {
        if token == "--jq" && index + 1 < tokens.len() {
            let expression = crate::codex_output_py::py_strip(&tokens[index + 1]);
            if JOB_ID_QUERY.is_match(expression) || FILTERED_JOB_ID_QUERY.is_match(expression) {
                return ValueKind::Number;
            }
        }
    }
    ValueKind::Text
}

/// `_safe_emitted_output_filter`.
pub(crate) fn safe_emitted_output_filter(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    match first.as_str() {
        "head" => return tokens.len() == 2 && bounded_count(&tokens[1], MAX_FILTER_LINES),
        "tail" => {
            return tokens.len() == 2 && bounded_count(&tokens[1], MAX_FAILED_LOG_TAIL_LINES);
        }
        "grep" | "rg" => {}
        _ => return false,
    }
    let mut positional: Vec<&String> = Vec::new();
    for token in &tokens[1..] {
        if token == "--no-config" {
            continue;
        }
        if token.starts_with('-') {
            let flags = token.trim_start_matches('-');
            if flags.is_empty()
                || flags
                    .chars()
                    .any(|flag| !matches!(flag, 'i' | 'n' | 'o' | 'q'))
            {
                return false;
            }
            continue;
        }
        positional.push(token);
    }
    positional.len() == 1
        && !["$", "`", "<(", ">("]
            .iter()
            .any(|marker| positional[0].contains(marker))
}

/// `_filters_bound_emitted_matches`.
pub(crate) fn filters_bound_emitted_matches(segments: &[Vec<String>]) -> bool {
    let final_segment = &segments[segments.len() - 1];
    if matches!(final_segment[0].as_str(), "head" | "tail") {
        return true;
    }
    matches!(final_segment[0].as_str(), "grep" | "rg")
        && final_segment[1..]
            .iter()
            .any(|token| token.starts_with('-') && token.trim_start_matches('-').contains('q'))
}

/// `_bounded_count`.
pub(crate) fn bounded_count(value: &str, maximum: u64) -> bool {
    let Some(normalized) = value.strip_prefix('-') else {
        return false;
    };
    decimal_digits_value(normalized).is_some_and(|count| (1..=maximum).contains(&count))
}

/// `_safe_log_metadata_grep`.
pub(crate) fn safe_log_metadata_grep(tokens: &[String]) -> bool {
    if tokens.len() != 3 || tokens[0] != "grep" || tokens[1] != "-iE" {
        return false;
    }
    let fields: Vec<&str> = tokens[2].split('|').collect();
    let mut unique = fields.clone();
    unique.sort_unstable();
    unique.dedup();
    unique.len() == fields.len()
        && fields
            .iter()
            .all(|field| LOG_METADATA_FIELDS.contains(field))
}

/// `_safe_run_log_metadata_args`.
pub(crate) fn safe_run_log_metadata_args(tokens: &[String]) -> bool {
    if tokens.is_empty() || tokens[0] != "gh" {
        return false;
    }
    let args = &tokens[1..];
    if args.len() < 2 || !matches!(args[0].as_str(), "-R" | "--repo") || !is_repository(&args[1]) {
        return false;
    }
    let args = &args[2..];
    args.len() == 4
        && args[0] == "run"
        && args[1] == "view"
        && is_positive_number(&args[2])
        && args[3] == "--log"
}

/// `_safe_text_filter_pipeline`.
pub(crate) fn safe_text_filter_pipeline(
    command_text: &str,
    values: &HashMap<String, ValueKind>,
) -> bool {
    let segments = pipeline_segments(command_text);
    segments.len() == 2
        && segments[0].first().is_some_and(|first| first == "echo")
        && safe_echo_tokens(&segments[0][1..], values)
        && safe_emitted_output_filter(&segments[1])
}

/// `_safe_echo`.
pub(crate) fn safe_echo(command_text: &str, values: &HashMap<String, ValueKind>) -> bool {
    let Some(tokens) = crate::codex_output_py::shlex_split(command_text) else {
        return false;
    };
    tokens.first().is_some_and(|first| first == "echo") && safe_echo_tokens(&tokens[1..], values)
}

/// `_safe_echo_tokens`.
pub(crate) fn safe_echo_tokens(tokens: &[String], values: &HashMap<String, ValueKind>) -> bool {
    for token in tokens {
        if ["$(", "`", "<(", ">(", ">", "<", ";", "&"]
            .iter()
            .any(|marker| token.contains(marker))
        {
            return false;
        }
        let unknown = VARIABLE
            .captures_iter(token)
            .any(|captures| variable_name(&captures).is_none_or(|name| !values.contains_key(name)));
        if unknown || VARIABLE.replace_all(token, "").contains('$') {
            return false;
        }
    }
    true
}
