//! `is_nonexecuting_github_actions_read_workflow` and the pipeline proofs it
//! relies on (`github_actions_read_workflow.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::{py_splitlines, py_strip, PyPath};
use crate::sfrs_gh_actions_env::{
    shell_read_execution_environment_is_safe, trusted_pipeline_executables,
};
use crate::sfrs_gh_actions_filters::{
    bounded_count, filters_bound_emitted_matches, github_output_kind, is_positive_number,
    is_repository, pipeline_segments, safe_actions_github_command, safe_echo,
    safe_emitted_output_filter, safe_log_metadata_grep, safe_run_log_metadata_args,
    safe_text_filter_pipeline, substitute_number_variables, without_safe_stderr_redirect,
    ValueKind, NAME,
};

const MAX_FILTER_LINES: u64 = 100;

static LITERAL_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\A(?P<name>{NAME})=(?P<value>[1-9][0-9]*)\z")).expect("literal")
});
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\A(?P<name>{NAME})=\$\((?P<body>.*)\)\z")).expect("assignment")
});
static LOOP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\Afor[\s\x1c-\x1f]+(?P<name>{NAME})[\s\x1c-\x1f]+in[\s\x1c-\x1f]+\$\((?P<body>.*)\);[\s\x1c-\x1f]*do\z"
    ))
    .expect("loop")
});
static CONDITIONAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\Aif[\s\x1c-\x1f]+(?P<body>.*);[\s\x1c-\x1f]*then\z").expect("conditional")
});

/// `is_nonexecuting_github_actions_read_workflow`.
pub(crate) fn is_nonexecuting_github_actions_read_workflow(
    command_text: &str,
    cwd: Option<&PyPath>,
    ctx: &Ctx,
) -> bool {
    if py_strip(command_text).is_empty()
        || command_text.contains('`')
        || command_text.contains("\\\n")
    {
        return false;
    }
    let env_text = |name: &str| ctx.host.env(name).unwrap_or_default();
    let host = env_text("GH_HOST");
    let host = py_strip(&host).to_lowercase();
    if !host.is_empty() && host != "github.com" {
        return false;
    }
    if ["GH_PAGER", "PAGER"].iter().any(|key| {
        let value = env_text(key);
        let value = py_strip(&value);
        !value.is_empty() && value != "cat"
    }) {
        return false;
    }
    if !py_strip(&env_text("RIPGREP_CONFIG_PATH")).is_empty() {
        return false;
    }
    let mut values: HashMap<String, ValueKind> = HashMap::new();
    let mut control_stack: Vec<&str> = Vec::new();
    let mut saw_github_read = false;
    for raw_line in py_splitlines(command_text) {
        let line = py_strip(&raw_line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(captures) = LITERAL_ASSIGNMENT.captures(line) {
            values.insert(captures["name"].to_owned(), ValueKind::Number);
            continue;
        }
        if let Some(captures) = ASSIGNMENT.captures(line) {
            let Some(kind) = safe_github_read_pipeline(&captures["body"], &values, cwd, ctx) else {
                return false;
            };
            values.insert(captures["name"].to_owned(), kind);
            saw_github_read = true;
            continue;
        }
        if let Some(captures) = LOOP.captures(line) {
            if safe_github_read_pipeline(&captures["body"], &values, cwd, ctx)
                != Some(ValueKind::Number)
            {
                return false;
            }
            values.insert(captures["name"].to_owned(), ValueKind::Number);
            control_stack.push("for");
            saw_github_read = true;
            continue;
        }
        if line == "done" {
            if control_stack.pop() != Some("for") {
                return false;
            }
            continue;
        }
        if let Some(captures) = CONDITIONAL.captures(line) {
            if !safe_text_filter_pipeline(&captures["body"], &values) {
                return false;
            }
            control_stack.push("if");
            continue;
        }
        if line == "fi" {
            if control_stack.pop() != Some("if") {
                return false;
            }
            continue;
        }
        if line.starts_with("echo ") || line == "echo" {
            if !safe_echo(line, &values) {
                return false;
            }
            continue;
        }
        if safe_github_read_pipeline(line, &values, cwd, ctx).is_none() {
            return false;
        }
        saw_github_read = true;
    }
    saw_github_read && control_stack.is_empty()
}

/// `_safe_github_read_pipeline`.
pub(crate) fn safe_github_read_pipeline(
    command_text: &str,
    values: &HashMap<String, ValueKind>,
    cwd: Option<&PyPath>,
    ctx: &Ctx,
) -> Option<ValueKind> {
    let segments = pipeline_segments(command_text);
    if segments.is_empty() || segments[0].is_empty() || segments[0][0] != "gh" {
        return None;
    }
    let execution_cwd = cwd.cloned().unwrap_or_else(|| ctx.process_cwd.clone());
    if !shell_read_execution_environment_is_safe(&execution_cwd, ctx) {
        return None;
    }
    if safe_actions_log_metadata_pipeline(&segments, &execution_cwd, ctx)
        || safe_failed_log_filter_pipeline(&segments, &execution_cwd, ctx)
    {
        return Some(ValueKind::Text);
    }
    let names: Vec<&str> = segments.iter().map(|segment| segment[0].as_str()).collect();
    if !trusted_pipeline_executables(&names, &execution_cwd, ctx) {
        return None;
    }
    let substituted = substitute_number_variables(&segments[0], values)?;
    let github_tokens = without_safe_stderr_redirect(&substituted)?;
    if !safe_actions_github_command(&github_tokens) {
        return None;
    }
    for segment in &segments[1..] {
        if !safe_emitted_output_filter(segment) {
            return None;
        }
    }
    if segments.len() > 1 && !filters_bound_emitted_matches(&segments[1..]) {
        return None;
    }
    Some(github_output_kind(&github_tokens))
}

/// `_safe_actions_log_metadata_pipeline`.
pub(crate) fn safe_actions_log_metadata_pipeline(
    segments: &[Vec<String>],
    cwd: &PyPath,
    ctx: &Ctx,
) -> bool {
    if segments.len() != 4 {
        return false;
    }
    let Some(github_tokens) = without_safe_stderr_redirect(&segments[0]) else {
        return false;
    };
    if !safe_run_log_metadata_args(&github_tokens) {
        return false;
    }
    let (grep, sort, head) = (&segments[1], &segments[2], &segments[3]);
    trusted_pipeline_executables(&["gh", "grep", "sort", "head"], cwd, ctx)
        && safe_log_metadata_grep(grep)
        && sort.len() == 2
        && sort[0] == "sort"
        && sort[1] == "-u"
        && head.len() == 2
        && head[0] == "head"
        && bounded_count(&head[1], MAX_FILTER_LINES)
}

/// `_safe_failed_log_filter_pipeline`.
pub(crate) fn safe_failed_log_filter_pipeline(
    segments: &[Vec<String>],
    cwd: &PyPath,
    ctx: &Ctx,
) -> bool {
    if segments.len() != 3 {
        return false;
    }
    let (github, search, tail) = (&segments[0], &segments[1], &segments[2]);
    if !(github.len() == 7
        && github[0] == "gh"
        && github[1] == "run"
        && github[2] == "view"
        && is_positive_number(&github[3])
        && github[4] == "--repo"
        && is_repository(&github[5])
        && github[6] == "--log-failed")
    {
        return false;
    }
    trusted_pipeline_executables(&["gh", "rg", "tail"], cwd, ctx)
        && safe_emitted_output_filter(search)
        && ((search.len() == 3 && search[0] == "rg" && search[1] == "-n")
            || (search.len() == 4
                && search[0] == "rg"
                && search[1] == "--no-config"
                && search[2] == "-n"))
        && safe_emitted_output_filter(tail)
        && tail[0] == "tail"
}
