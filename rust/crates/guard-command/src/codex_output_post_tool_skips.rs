//! When credential-looking post-tool output is expected: a read-only source
//! inspection or structured native search over fixture text
//! (`_codex_source_inspection_can_skip_secret_output`,
//! `commands_support_native_search.py`) and a focused pytest run printing
//! fixture keys (`_codex_focused_pytest_can_skip_secret_output`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::codex_output_commands::is_focused_pytest_verification;
use crate::codex_output_entry::{scope_of, secret_like_source_name};
use crate::codex_output_fs as pyfs;
use crate::codex_output_inspection_flow::is_read_only_source_inspection;
use crate::codex_output_post_tool::{absolute, Input, PostToolError, Run};
use crate::codex_output_post_tool_sources::sensitive_local_source_matches;
use crate::codex_output_py::{py_splitlines, py_strip, shlex_split, PyPath};
use crate::codex_output_source_paths::resolve_source_candidate_path;
use crate::sfrs_read_only_filters::read_only_lookup_target_is_safe;

const NATIVE_SEARCH_TOOLS: [&str; 4] = ["grep", "egrep", "fgrep", "rg"];
const EXPLICIT_COMMAND_KEYS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
const PATTERN_KEYS: [&str; 4] = ["pattern", "query", "search", "regex"];
const TARGET_KEYS: [&str; 6] = [
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
];
const PLURAL_TARGET_KEYS: [&str; 2] = ["paths", "files"];
const GLOB_KEYS: [&str; 3] = ["glob", "include", "includes"];
/// `SOURCE_INSPECTION_BENIGN_DOTFILES | {".worktrees"}`.
const BENIGN_SOURCE_DOTFILES: [&str; 2] = [".nvmrc", ".worktrees"];

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("post-tool skip pattern"))
}

fn private_key_fixture() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?P<body>.*?)-----END [A-Z ]*PRIVATE KEY-----",
    )
}

fn private_key_fixture_body() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"(?i)\b(?:secret-key-material|fixture|fake|example|sample|dummy|test-key|placeholder)\b",
    )
}

fn benign_fixture_assignment() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r#"(?i)\A\s*fake[_-]?(?:credential|secret|token)\s*[:=]\s*(?:"[^\r\n"]*"|'[^\r\n']*'|[^\s"',}]+)\s*\z"#,
    )
}

fn pytest_progress_line() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"\A[.FEsxXrR]+\z")
}

fn pytest_summary_line() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"(?i)\A(?:=+\s.*\s=+|collected\s+\d+\s+items(?:\s*/\s*\d+\s+deselected)?|(?:\d+\s+\w+(?:,\s*\d+\s+\w+)*)\s+in\s+\d+(?:\.\d+)?s|.+::.+\s+(?:PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS))\z",
    )
}

/// `output_uses_placeholder_private_key_fixture`: every PEM block is the
/// known placeholder fixture.
fn uses_placeholder_private_key_fixture(response_text: &str) -> bool {
    let mut matched = false;
    for captures in private_key_fixture().captures_iter(response_text) {
        matched = true;
        let lines: Vec<String> = py_splitlines(&captures["body"])
            .iter()
            .map(|line| py_strip(line))
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        let body = lines.join(" ").replace("\\n", " ").replace("\\r", " ");
        if !private_key_fixture_body().is_match(&body) {
            return false;
        }
    }
    matched
}

/// `_codex_output_is_only_benign_secret_fixture`.
fn is_only_benign_secret_fixture(response_text: &str) -> bool {
    let lines: Vec<String> = py_splitlines(response_text)
        .into_iter()
        .filter(|line| !py_strip(line).is_empty())
        .collect();
    !lines.is_empty()
        && lines
            .iter()
            .all(|line| benign_fixture_assignment().is_match(line))
}

/// `_codex_focused_pytest_output_is_only_benign_fixture`.
fn focused_pytest_output_is_only_benign_fixture(response_text: &str) -> bool {
    let mut saw_fixture = false;
    for raw in py_splitlines(response_text) {
        let line = py_strip(&raw);
        if line.is_empty() {
            continue;
        }
        if is_only_benign_secret_fixture(line) {
            saw_fixture = true;
            continue;
        }
        if pytest_progress_line().is_match(line) || pytest_summary_line().is_match(line) {
            continue;
        }
        return false;
    }
    saw_fixture
}

/// `_codex_command_references_benign_source_dotfile`.
fn references_benign_source_dotfile(command: &str) -> bool {
    shlex_split(command).is_some_and(|parts| {
        parts.iter().any(|part| {
            BENIGN_SOURCE_DOTFILES.contains(&PyPath::new(part).name().to_lowercase().as_str())
        })
    })
}

/// Content matches above `medium` are all placeholder PEM fixtures; `None`
/// when there are none.
fn high_matches_are_placeholder_keys(content: &[Value], response_text: &str) -> Option<bool> {
    let high: Vec<&Value> = content
        .iter()
        .filter(|item| item["sensitivity"].as_str() != Some("medium"))
        .collect();
    if high.is_empty() {
        return None;
    }
    Some(
        high.iter()
            .all(|item| item["classifier"].as_str() == Some("pem-private-key"))
            && uses_placeholder_private_key_fixture(response_text),
    )
}

/// `_nonempty_string`.
fn nonempty(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !py_strip(text).is_empty())
}

/// `value in (None, False)` with Python equality (`0 == False`).
fn none_or_false(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => true,
        Some(Value::Number(number)) => number.as_f64() == Some(0.0),
        _ => false,
    }
}

fn os_path(path: Option<&PyPath>) -> Option<PathBuf> {
    path.map(|path| PathBuf::from(path.to_string()))
}

/// `_native_search_targets`.
fn native_search_targets(tool_input: &Map<String, Value>) -> Option<Vec<String>> {
    let mut targets = Vec::new();
    for key in TARGET_KEYS {
        if let Some(value) = tool_input.get(key) {
            targets.push(py_strip(nonempty(value)?).to_owned());
        }
    }
    for key in PLURAL_TARGET_KEYS {
        let Some(value) = tool_input.get(key) else {
            continue;
        };
        let items = value.as_array().filter(|items| !items.is_empty())?;
        for item in items {
            nonempty(item)?;
        }
        targets.extend(
            items
                .iter()
                .filter_map(nonempty)
                .map(|text| py_strip(text).to_owned()),
        );
    }
    Some(targets)
}

/// `_native_search_target_is_safe`.
fn native_search_target_is_safe(
    run: &Run,
    input: &Input,
    target: &str,
    home: Option<&Path>,
) -> bool {
    if target.contains(['*', '?', '[', ']']) || !read_only_lookup_target_is_safe(target, true, home)
    {
        return false;
    }
    let Some(candidate) =
        resolve_source_candidate_path(target, input.cwd.as_ref(), input.home_dir.as_ref(), run.ctx)
    else {
        return false;
    };
    let candidate = absolute(run.ctx, &candidate);
    if pyfs::exists(&candidate) != Ok(true) {
        return false;
    }
    let Some(resolved) = pyfs::resolve(&candidate) else {
        return false;
    };
    (pyfs::is_file(&resolved) == Ok(true) || pyfs::is_dir(&resolved) == Ok(true))
        && read_only_lookup_target_is_safe(&resolved.to_string(), true, home)
}

/// `native_post_tool_search_is_read_only`.
fn native_search_is_read_only(run: &Run, input: &Input) -> bool {
    let tool = match input.tool_name() {
        Value::String(name) => py_strip(name).to_lowercase(),
        _ => return false,
    };
    let Some(tool_input) = input.tool_input.as_object() else {
        return false;
    };
    if !NATIVE_SEARCH_TOOLS.contains(&tool.as_str())
        || EXPLICIT_COMMAND_KEYS
            .iter()
            .any(|key| tool_input.get(*key).and_then(nonempty).is_some())
    {
        return false;
    }
    let patterns: Vec<&Value> = PATTERN_KEYS
        .iter()
        .filter_map(|key| tool_input.get(*key))
        .collect();
    if patterns.is_empty() || patterns.iter().any(|value| nonempty(value).is_none()) {
        return false;
    }
    if !none_or_false(tool_input.get("follow")) || !none_or_false(tool_input.get("hidden")) {
        return false;
    }
    let home = os_path(input.home_dir.as_ref());
    let globs_safe = GLOB_KEYS
        .iter()
        .filter_map(|key| tool_input.get(*key))
        .all(|value| {
            nonempty(value)
                .is_some_and(|glob| read_only_lookup_target_is_safe(glob, false, home.as_deref()))
        });
    if !globs_safe {
        return false;
    }
    let Some(mut targets) = native_search_targets(tool_input) else {
        return false;
    };
    if targets.is_empty() {
        targets.push(".".to_owned());
    }
    targets
        .iter()
        .all(|target| native_search_target_is_safe(run, input, target, home.as_deref()))
}

/// The command reads no local secret and names no secret-like source.
fn names_no_secret_source(
    run: &Run,
    input: &Input,
    command: &str,
    exec_context: bool,
) -> Result<bool, PostToolError> {
    let cwd = input.cwd.as_ref();
    if !sensitive_local_source_matches(run, command, cwd, false)?.is_empty() {
        return Ok(false);
    }
    run.check()?;
    Ok(!secret_like_source_name(
        run.ctx,
        command,
        cwd,
        input.home_dir.as_ref(),
        exec_context,
        false,
    ))
}

/// `_codex_source_inspection_can_skip_secret_output`.
pub(crate) fn source_inspection_can_skip(
    run: &Run,
    input: &Input,
    command: &str,
    content: &[Value],
) -> Result<bool, PostToolError> {
    let scope = scope_of(run.ctx, input.cwd.as_ref(), input.home_dir.as_ref());
    let read_only =
        is_read_only_source_inspection(command, scope) || native_search_is_read_only(run, input);
    if !read_only || !names_no_secret_source(run, input, command, false)? {
        return Ok(false);
    }
    if let Some(skip) = high_matches_are_placeholder_keys(content, &input.response_text) {
        return Ok(skip);
    }
    if references_benign_source_dotfile(command) {
        return Ok(is_only_benign_secret_fixture(&input.response_text));
    }
    Ok(true)
}

/// `_codex_focused_pytest_can_skip_secret_output`.
pub(crate) fn focused_pytest_can_skip(
    run: &Run,
    input: &Input,
    command: &str,
    content: &[Value],
) -> Result<bool, PostToolError> {
    run.check()?;
    if !is_focused_pytest_verification(command)
        || !names_no_secret_source(run, input, command, true)?
    {
        return Ok(false);
    }
    Ok(
        high_matches_are_placeholder_keys(content, &input.response_text)
            .unwrap_or_else(|| focused_pytest_output_is_only_benign_fixture(&input.response_text)),
    )
}

#[cfg(all(test, unix))]
#[path = "codex_output_post_tool_search_tests.rs"]
mod search_tests;

#[cfg(test)]
mod tests {
    use super::{
        focused_pytest_output_is_only_benign_fixture, is_only_benign_secret_fixture,
        uses_placeholder_private_key_fixture,
    };

    #[test]
    fn fixture_output_shapes_follow_the_python_patterns() {
        assert!(is_only_benign_secret_fixture(
            "FAKE_TOKEN=abc\n  fake-secret: 'x'\n"
        ));
        assert!(!is_only_benign_secret_fixture("TOKEN=abc"));
        assert!(focused_pytest_output_is_only_benign_fixture(
            "..F.\nfake_token=abc\n1 passed, 2 failed in 0.12s\n"
        ));
        assert!(!focused_pytest_output_is_only_benign_fixture(
            "1 passed in 0.1s"
        ));
        let fence = concat!("PRIVATE ", "KEY-----");
        let fixture = format!("-----BEGIN {fence}\nfixture\n-----END {fence}");
        assert!(uses_placeholder_private_key_fixture(&fixture));
        let real = format!("-----BEGIN RSA {fence}\nMIIEow\n-----END RSA {fence}");
        assert!(!uses_placeholder_private_key_fixture(&format!(
            "{fixture}\n{real}"
        )));
    }
}
