//! Generated Node workflow and inline evaluation safety
//! (`node_generated_workflows.py`: GraphQL query-file workflows, Node inline
//! eval scans and find/fd action checks).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
#[cfg(unix)]
use crate::contained_runner::common::normpath;
use crate::false_positive_rules::fd_arg_requests_exec;
#[cfg(windows)]
use crate::home_path_text::normpath_nt as normpath;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_developer_inspection::{
    fd_exec_sed_read_only_args_are_safe, find_args_use_write_or_unsafe_exec_action,
};
use crate::sfrs_gh_body_safety::path_text_looks_sensitive;
use crate::sfrs_node_redaction::contains_destructive_node_inline_script;
use crate::sfrs_patterns::{NODE_INLINE_EVAL_FLAGS, NODE_OPTION_FLAGS_WITH_VALUE};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};
use crate::sfrs_typescript_graphql::{
    contains_shell_expansion, graphql_query_file_substitution_refs,
    graphql_workflow_field_arg_is_safe, strip_shell_quotes,
    SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN,
};

static QUERY_WORD: LazyLock<FancyRegex> = LazyLock::new(|| compile_fancy(r"\bquery\b"));
static MUTATION_WORD: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r"\bmutation\b|\bsubscription\b"));

/// `_looks_like_safe_graphql_query_file_workflow`. A matcher failure is "not
/// safe".
pub(crate) fn looks_like_safe_graphql_query_file_workflow(command_text: &str, ctx: &Ctx) -> bool {
    let Ok(Some(captures)) = SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN.captures(command_text) else {
        return false;
    };
    let path = captures.name("path").map_or("", |group| group.as_str());
    let target_path = strip_shell_quotes(py_strip(path));
    if !target_path.ends_with(".graphql")
        || path_text_looks_sensitive(target_path)
        || contains_shell_expansion(target_path)
        || !looks_like_temporary_pr_threads_query_path(target_path, ctx)
    {
        return false;
    }
    let body = py_strip(captures.name("body").map_or("", |group| group.as_str()));
    let Ok(has_query) = QUERY_WORD.is_match(body) else {
        return false;
    };
    let Ok(has_mutation) = MUTATION_WORD.is_match(body) else {
        return false;
    };
    if !has_query || has_mutation {
        return false;
    }
    let rest = py_strip(captures.name("rest").map_or("", |group| group.as_str()));
    if !rest.starts_with("gh api graphql ") || rest.contains([';', '&', '|', '>', '<', '\n']) {
        return false;
    }
    let mut remaining = rest.to_owned();
    for reference in graphql_query_file_substitution_refs(target_path) {
        remaining = remaining.replace(&reference, "");
    }
    if remaining.contains("$(") || remaining.contains('`') {
        return false;
    }
    graphql_workflow_rest_args_are_safe(rest, target_path)
}

/// `_graphql_workflow_rest_args_are_safe`.
pub(crate) fn graphql_workflow_rest_args_are_safe(rest: &str, target_path: &str) -> bool {
    let parts = split_shell_parts(rest);
    if parts.len() < 3 || parts[..3] != ["gh", "api", "graphql"] {
        return false;
    }
    let mut saw_query_arg = false;
    let mut index = 3;
    while index < parts.len() {
        let token = parts[index].as_str();
        if token == "--" {
            return false;
        }
        if matches!(token, "-F" | "--field" | "-f" | "--raw-field") {
            let Some(argument) = parts.get(index + 1) else {
                return false;
            };
            if !graphql_workflow_field_arg_is_safe(argument, target_path) {
                return false;
            }
            if argument.starts_with("query=") {
                saw_query_arg = true;
            }
            index += 2;
            continue;
        }
        let value = if token.starts_with("--field=") || token.starts_with("--raw-field=") {
            token.split_once('=').map_or("", |(_, value)| value)
        } else if (token.starts_with("-F") || token.starts_with("-f")) && token.chars().count() > 2
        {
            &token[2..]
        } else {
            return false;
        };
        if !graphql_workflow_field_arg_is_safe(value, target_path) {
            return false;
        }
        if value.starts_with("query=") {
            saw_query_arg = true;
        }
        index += 1;
    }
    saw_query_arg
}

const TEMP_GROUPS: &[&[&str]] = &[
    &["/tmp/", "/private/tmp/"],
    &["/var/tmp/", "/private/var/tmp/"],
    &["/var/folders/", "/private/var/folders/"],
];

fn temp_group_index(lowered: &str) -> Option<usize> {
    TEMP_GROUPS
        .iter()
        .position(|group| group.iter().any(|prefix| lowered.starts_with(prefix)))
}

/// `_looks_like_temporary_pr_threads_query_path`. Existence and the resolved
/// path are host facts; a host that cannot answer rejects the path.
pub(crate) fn looks_like_temporary_pr_threads_query_path(path_text: &str, ctx: &Ctx) -> bool {
    let normalized = normpath(&path_text.replace('\\', "/")).replace('\\', "/");
    let basename = normalized.rsplit('/').next().unwrap_or("");
    if basename != "pr-threads-query.graphql" || !normalized.starts_with('/') {
        return false;
    }
    if ctx.host.path_exists(&normalized) {
        return false;
    }
    let Some(literal_group) = temp_group_index(&normalized.to_lowercase()) else {
        return false;
    };
    let Some(resolved) = ctx.host.real_path(&normalized) else {
        return false;
    };
    temp_group_index(&resolved.replace('\\', "/").to_lowercase()) == Some(literal_group)
}

/// `_contains_destructive_node_inline_eval`.
pub(crate) fn contains_destructive_node_inline_eval(parts: &[String]) -> bool {
    iter_shell_command_segments(parts).iter().any(|segment| {
        matches!(
            shell_segment_primary_command(segment),
            (Some(name), Some(index))
                if name == "node"
                    && segment_contains_destructive_node_inline_eval(&segment[index + 1..])
        )
    })
}

/// `_find_or_fd_uses_write_or_exec_action`.
pub(crate) fn find_or_fd_uses_write_or_exec_action(
    parts: &[String],
    home_dir: Option<&Path>,
) -> bool {
    for segment in iter_shell_command_segments(parts) {
        let (Some(name), Some(index)) = shell_segment_primary_command(&segment) else {
            continue;
        };
        let args = &segment[index + 1..];
        if name == "find" && find_args_use_write_or_unsafe_exec_action(args) {
            return true;
        }
        if name == "fd"
            && args.iter().any(|arg| fd_arg_requests_exec(arg))
            && !fd_exec_sed_read_only_args_are_safe(args, home_dir)
        {
            return true;
        }
    }
    false
}

/// `_is_combined_node_inline_eval_flag`.
pub(crate) fn is_combined_node_inline_eval_flag(token: &str) -> bool {
    matches!(token, "-pe" | "-ep")
}

/// `_segment_contains_destructive_node_inline_eval`.
pub(crate) fn segment_contains_destructive_node_inline_eval(segment_args: &[String]) -> bool {
    let lowered: Vec<String> = segment_args.iter().map(|arg| arg.to_lowercase()).collect();
    let mut index = 0;
    while index < lowered.len() {
        let token = lowered[index].as_str();
        let has_next = index + 1 < lowered.len();
        if token == "--" {
            break;
        }
        if NODE_INLINE_EVAL_FLAGS.contains(&token) && has_next {
            if matches!(token, "-p" | "--print") && lowered[index + 1].starts_with('-') {
                index += 1;
                continue;
            }
            if contains_destructive_node_inline_script(&segment_args[index + 1]) {
                return true;
            }
            index += 2;
            continue;
        }
        if is_combined_node_inline_eval_flag(token) && has_next {
            if contains_destructive_node_inline_script(&segment_args[index + 1]) {
                return true;
            }
            index += 2;
            continue;
        }
        if token.starts_with("--eval=") || token.starts_with("--print=") {
            let value = segment_args[index].split_once('=').map_or("", |(_, v)| v);
            if contains_destructive_node_inline_script(value) {
                return true;
            }
            index += 1;
            continue;
        }
        if (token.starts_with("-e") || token.starts_with("-p"))
            && !NODE_INLINE_EVAL_FLAGS.contains(&token)
        {
            if contains_destructive_node_inline_script(&segment_args[index][2..]) {
                return true;
            }
            index += 1;
            continue;
        }
        if NODE_OPTION_FLAGS_WITH_VALUE.contains(&token) && has_next {
            index += 2;
            continue;
        }
        if !token.starts_with('-') {
            break;
        }
        index += 1;
    }
    false
}
