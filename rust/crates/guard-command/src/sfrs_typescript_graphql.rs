//! Temporary TypeScript and GraphQL workflow safety
//! (`typescript_graphql_safety.py`, everything except the Node script
//! redaction in `sfrs_node_redaction`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_constants::{PYTEST_UNSAFE_ENV_KEYS, UNMODELED_INLINE_INTERPRETER_COMMANDS};
use crate::sfrs_gh_body_safety::text_contains_credential_exfiltration;
use crate::sfrs_interpreter_heredoc::{
    shell_heredoc_payloads, single_interpreter_heredoc_interpreter,
};
use crate::sfrs_interpreter_scripts::{is_script_interpreter_command, script_interpreter_texts};
use crate::sfrs_node_redaction::node_script_contains_sensitive_runtime_behavior;
use crate::sfrs_pytest_binary::pytest_binary_segment_is_safe;
use crate::sfrs_pytest_env::shell_segment_sets_env_key;
use crate::sfrs_pytest_wrappers::{
    shell_segment_uses_cwd_changing_wrapper, shell_segment_uses_env_split_string_wrapper,
};
use crate::sfrs_shell_tokens::{iter_shell_command_segments, shell_segment_primary_command};

/// Python `\s` also matches 0x1c-0x1f.
fn py_ws(pattern: &str) -> String {
    pattern
        .replace("<NS>", r"[^\s\x1c-\x1f]")
        .replace("<S>", r"[\s\x1c-\x1f]")
}

/// `_SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN` (anchored at both ends).
pub(crate) static SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN: LazyLock<FancyRegex> =
    LazyLock::new(|| {
        compile_fancy(&py_ws(concat!(
            r#"(?s)\A<S>*cat<S>*><S>*(?P<path>'[^']+'|"[^"]+"|<NS>+)<S>*"#,
            r#"<<(?P<quote>['"])(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"#,
            r#"<S>*\n(?P<body>.*?)\n(?P=label)<S>*(?:\n|&&|;)<S>*(?P<rest>.+)\z"#,
        )))
    });

/// `_CONTAINED_TEMP_TYPESCRIPT_WORKFLOW_PATTERN`.
pub(crate) static CONTAINED_TEMP_TYPESCRIPT_WORKFLOW_PATTERN: LazyLock<FancyRegex> = LazyLock::new(
    || {
        compile_fancy(&py_ws(concat!(
            r#"(?s)\A<S>*cat<S>*><S>*(?P<path>scripts/tmp-[A-Za-z0-9._-]+\.tsx?)<S>*"#,
            r#"<<(?P<quote>['"])(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)<S>*\n"#,
            r#"(?P<body>.*?)\n(?P=label)<S>*(?:\n|&&|;)<S>*"#,
            r#"timeout<S>+(?P<timeout>[1-9][0-9]{0,2})<S>+npx<S>+(?:--no-install<S>+)?tsx<S>+(?P=path)"#,
            r#"(?:<S>+2>&1)?(?:<S>*\|<S>*(?:grep<S>+-v<S>+(?:'[^']*'|"[^"]*")|head<S>+-[1-9][0-9]*|tail<S>+-[1-9][0-9]*))*"#,
            r#"<S>*;<S>*rm<S>+-f<S>+(?P=path)<S>*\z"#,
        )))
    },
);

static SHELL_VARIABLE: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r"\$[A-Za-z_][A-Za-z0-9_]*"));
static SHELL_GLOB: LazyLock<FancyRegex> = LazyLock::new(|| compile_fancy(r"[*?\[\]{}]"));

/// `_looks_like_contained_temporary_typescript_workflow`. A matcher failure
/// is "not contained".
pub(crate) fn looks_like_contained_temporary_typescript_workflow(command_text: &str) -> bool {
    let Ok(Some(captures)) = CONTAINED_TEMP_TYPESCRIPT_WORKFLOW_PATTERN.captures(command_text)
    else {
        return false;
    };
    let timeout: u32 = captures
        .name("timeout")
        .and_then(|group| group.as_str().parse().ok())
        .unwrap_or(u32::MAX);
    if timeout > 300 {
        return false;
    }
    let body = captures.name("body").map_or("", |group| group.as_str());
    if body.len() > 64 * 1024 || body.contains('\0') {
        return false;
    }
    !(text_contains_credential_exfiltration(body)
        || node_script_contains_sensitive_runtime_behavior(body))
}

/// `_strip_shell_quotes`.
pub(crate) fn strip_shell_quotes(value: &str) -> &str {
    let mut chars = value.chars();
    match (chars.next(), chars.next_back()) {
        (Some(first), Some(last)) if first == last && (first == '\'' || first == '"') => {
            &value[1..value.len() - 1]
        }
        _ => value,
    }
}

/// `_contains_shell_expansion`. A matcher failure counts as an expansion.
pub(crate) fn contains_shell_expansion(value: &str) -> bool {
    value.contains("$(")
        || value.contains('`')
        || value.contains("${")
        || value.contains("$'")
        || value.contains("$\"")
        || SHELL_VARIABLE.is_match(value).unwrap_or(true)
        || SHELL_GLOB.is_match(value).unwrap_or(true)
}

/// `_graphql_query_file_substitution_refs`.
pub(crate) fn graphql_query_file_substitution_refs(target_path: &str) -> BTreeSet<String> {
    [
        format!("$(cat {target_path})"),
        format!("$(cat \"{target_path}\")"),
        format!("$(cat '{target_path}')"),
    ]
    .into_iter()
    .collect()
}

/// `_graphql_query_file_argument_values`.
pub(crate) fn graphql_query_file_argument_values(target_path: &str) -> BTreeSet<String> {
    let mut values = graphql_query_file_substitution_refs(target_path);
    values.insert(format!("@{target_path}"));
    values
}

/// `_graphql_workflow_field_arg_is_safe`.
pub(crate) fn graphql_workflow_field_arg_is_safe(argument: &str, target_path: &str) -> bool {
    let Some((name, value)) = argument.split_once('=') else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    if name == "query" {
        return graphql_query_file_argument_values(target_path).contains(value);
    }
    if value.is_empty() || value.starts_with('@') {
        return false;
    }
    !(contains_shell_expansion(value) || value.contains('/') || value.contains('\\'))
}

/// `_contains_unsafe_pytest_binary_invocation`.
pub(crate) fn contains_unsafe_pytest_binary_invocation(
    parts: &[String],
    cwd: Option<&Path>,
) -> bool {
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(index)) = shell_segment_primary_command(&segment) else {
            continue;
        };
        if command_name != "pytest" {
            continue;
        }
        if shell_segment_sets_env_key(&segment, index, "PATH")
            || PYTEST_UNSAFE_ENV_KEYS
                .iter()
                .any(|key| shell_segment_sets_env_key(&segment, index, key))
            || shell_segment_uses_env_split_string_wrapper(&segment, index)
            || shell_segment_uses_cwd_changing_wrapper(&segment, index)
            || !pytest_binary_segment_is_safe(&segment[index], &segment[index + 1..], cwd)
        {
            return true;
        }
    }
    false
}

/// `_contains_unmodeled_inline_interpreter_eval`.
pub(crate) fn contains_unmodeled_inline_interpreter_eval(
    command_text: &str,
    parts: &[String],
    command_names: &[String],
) -> bool {
    if let Some(interpreter) = single_interpreter_heredoc_interpreter(command_text) {
        return is_unmodeled_inline_interpreter_command(&interpreter);
    }
    if command_names.is_empty()
        || !command_names
            .iter()
            .all(|name| is_script_interpreter_command(name))
        || !command_names
            .iter()
            .any(|name| is_unmodeled_inline_interpreter_command(name))
    {
        return false;
    }
    !script_interpreter_texts(parts).is_empty() || !shell_heredoc_payloads(command_text).is_empty()
}

/// `_is_unmodeled_inline_interpreter_command`.
pub(crate) fn is_unmodeled_inline_interpreter_command(command_name: &str) -> bool {
    UNMODELED_INLINE_INTERPRETER_COMMANDS.contains(&command_name)
}
