//! Port of `encoded_payloads._looks_destructive_shell_command`: whether a
//! shell command can mutate local state, run unreviewed code or otherwise needs
//! review, after every read-only shape Guard recognises has been ruled out.

// Consumed by the dispatcher slice.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
use crate::sfrs_constants::{DESTRUCTIVE_SHELL_COMMANDS, SAFE_STATIC_SHELL_COMMANDS};
use crate::sfrs_destructive::{
    contains_destructive_git_command, contains_mutating_shell_redirection,
    find_command_uses_delete, redacted_shell_text_for_command_names, shell_command_names,
    shell_command_names_from_parts, shell_text_for_redirection_scan,
};
use crate::sfrs_developer_inspection::static_shell_segment_is_safe;
use crate::sfrs_encoded_payloads::looks_like_read_only_shell_pipeline;
use crate::sfrs_git_audit::is_read_only_git_ancestry_audit;
use crate::sfrs_interpreter_heredoc::single_interpreter_heredoc_script;
use crate::sfrs_interpreter_observers::{
    contains_pytest_env_shell_script_wrapper, looks_like_benign_interpreter_wait,
    looks_like_benign_interpreter_wait_chain, looks_like_read_only_interpreter_command,
    looks_like_read_only_interpreter_compound, looks_like_safe_read_only_lookup_command,
    read_only_lookup_segments,
};
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_node_heredoc::{
    looks_like_safe_node_generated_file_heredoc, looks_like_safe_node_read_only_http_heredoc,
};
use crate::sfrs_node_redaction::node_script_contains_sensitive_runtime_behavior;
use crate::sfrs_node_templates::single_node_heredoc_script;
use crate::sfrs_node_workflows::{
    contains_destructive_node_inline_eval, find_or_fd_uses_write_or_exec_action,
    looks_like_safe_graphql_query_file_workflow,
};
use crate::sfrs_perl_read_only::looks_like_read_only_perl_filter;
use crate::sfrs_pytest_binary::{
    contains_prior_pytest_state_mutation, contains_pytest_process_substitution,
    contains_unsafe_pytest_environment_wrapper, is_literal_cat_heredoc_to_stdout,
    looks_like_safe_pytest_binary_invocation, looks_like_supported_python_invocation,
};
use crate::sfrs_routine_move::looks_like_safe_routine_move;
use crate::sfrs_shell_tokens::{shell_segment_primary_command, split_shell_parts};
use crate::sfrs_substitution::{
    env_split_string_payloads, shell_command_scripts, shell_command_substitution_payloads,
};
use crate::sfrs_typescript_graphql::{
    contains_unmodeled_inline_interpreter_eval, contains_unsafe_pytest_binary_invocation,
    looks_like_contained_temporary_typescript_workflow,
};
use crate::shell_execution_context::{
    model_shell_execution_context, validate_shell_execution_segment, ShellExecutionContext,
};
use crate::shell_structure::extract_heredocs;

/// `Path(text).name.lower()`.
fn path_name_lower(text: &str) -> String {
    let trimmed = text.trim_end_matches('/');
    trimmed
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

/// `native_critical_floor_action(...) == "block"`; every failure blocks.
fn critical_floor_blocks(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if command_text.len() > crate::MAX_COMMAND_BYTES || command_text.contains('\0') {
        return true;
    }
    let process_cwd = PathBuf::from(ctx.process_cwd.to_string());
    let default_home = PathBuf::from(ctx.default_home.to_string());
    crate::critical_floor_action(
        command_text,
        cwd.unwrap_or(&process_cwd),
        home_dir.unwrap_or(&default_home),
    )
    .map_or(true, |action| action.as_str() == "block")
}

/// `_looks_destructive_shell_command` with its keyword defaults.
pub(crate) fn looks_destructive_shell_command(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    destructive(command_text, cwd, home_dir, ctx, None, false, 0)
}

/// `_looks_destructive_shell_command(..., execution_context=context)`.
pub(crate) fn looks_destructive_shell_command_in(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
    execution_context: &ShellExecutionContext,
) -> bool {
    destructive(
        command_text,
        cwd,
        home_dir,
        ctx,
        Some(execution_context),
        false,
        0,
    )
}

fn destructive(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
    execution_context: Option<&ShellExecutionContext>,
    execution_context_applied: bool,
    depth: usize,
) -> bool {
    if depth > 4 {
        return true;
    }
    let normalized = py_strip(command_text);
    if normalized.is_empty() {
        return false;
    }
    if let Some(home) = home_dir {
        if is_read_only_git_ancestry_audit(normalized, cwd, home, ctx) {
            return false;
        }
    }
    let guard_token_present = split_shell_parts(normalized).iter().any(|part| {
        let name = path_name_lower(part);
        let name = name.strip_suffix(".exe").unwrap_or(&name);
        matches!(name, "hol-guard" | "plugin-guard")
    });
    if guard_token_present && critical_floor_blocks(normalized, cwd, home_dir, ctx) {
        return true;
    }
    let nested = |text: &str, nested_cwd: Option<&Path>, applied: bool| {
        destructive(text, nested_cwd, home_dir, ctx, None, applied, depth + 1)
    };
    if !execution_context_applied {
        let modeled;
        let execution_context = match execution_context {
            Some(context) => context,
            None => {
                modeled = model_shell_execution_context(normalized, cwd, cwd, None);
                &modeled
            }
        };
        if execution_context.directory_change_present {
            if !execution_context.complete {
                return true;
            }
            let has_heredoc = !extract_heredocs(normalized).is_empty();
            let mut heredoc_segment_cwds: Vec<PathBuf> = Vec::new();
            for segment in &execution_context.segments {
                if segment.directory_operation.is_some() {
                    continue;
                }
                let (segment_cwd, validation_reason) =
                    validate_shell_execution_segment(execution_context, segment);
                let Some(segment_cwd) = segment_cwd.filter(|_| validation_reason.is_none()) else {
                    return true;
                };
                if let (Some(name), Some(index)) = shell_segment_primary_command(&segment.tokens) {
                    if SAFE_STATIC_SHELL_COMMANDS.contains(&name.as_str())
                        && !static_shell_segment_is_safe(&segment.tokens[index + 1..])
                    {
                        return true;
                    }
                }
                if segment.tokens.iter().any(|token| token.starts_with("<<")) {
                    heredoc_segment_cwds.push(segment_cwd);
                } else if nested(&segment.command_text(), Some(&segment_cwd), true) {
                    return true;
                }
            }
            if has_heredoc {
                if heredoc_segment_cwds.len() != 1 {
                    return true;
                }
                return nested(normalized, Some(&heredoc_segment_cwds[0]), true);
            }
            let contextual_parts = split_shell_parts(normalized);
            return contains_prior_pytest_state_mutation(&contextual_parts)
                || contains_pytest_env_shell_script_wrapper(&contextual_parts);
        }
    }
    if is_literal_cat_heredoc_to_stdout(normalized) {
        return false;
    }
    if shell_command_substitution_payloads(normalized)
        .iter()
        .any(|payload| nested(payload, cwd, false))
    {
        return true;
    }
    if let Some(script) = single_node_heredoc_script(normalized) {
        if looks_like_safe_node_read_only_http_heredoc(normalized, &script)
            || looks_like_safe_node_generated_file_heredoc(normalized, &script)
        {
            return false;
        }
        return node_script_contains_sensitive_runtime_behavior(&script);
    }
    if looks_like_contained_temporary_typescript_workflow(normalized)
        || looks_like_safe_graphql_query_file_workflow(normalized, ctx)
    {
        return false;
    }
    let parts = split_shell_parts(normalized);
    if parts.is_empty() {
        return false;
    }
    let lowered = normalized.to_lowercase();
    let redacted_command_text = redacted_shell_text_for_command_names(&lowered);
    let redirection_parts = split_shell_parts(&shell_text_for_redirection_scan(&lowered));
    if contains_mutating_shell_redirection(&redirection_parts)
        || contains_prior_pytest_state_mutation(&parts)
        || contains_pytest_env_shell_script_wrapper(&parts)
        || contains_pytest_process_substitution(normalized, &parts)
        || contains_unsafe_pytest_environment_wrapper(&parts)
    {
        return true;
    }
    let pipeline_check = |text: &str, segment_cwd: Option<&Path>, segment_home: Option<&Path>| {
        destructive(text, segment_cwd, segment_home, ctx, None, false, 0)
    };
    if looks_like_safe_read_only_lookup_command(normalized, &parts, home_dir, ctx)
        || looks_like_read_only_shell_pipeline(normalized, &parts, cwd, home_dir, &pipeline_check)
        || looks_like_read_only_interpreter_compound(normalized, &parts, home_dir, ctx)
    {
        return false;
    }
    let raw_command_names = shell_command_names(&redacted_command_text);
    let parsed_command_names = shell_command_names_from_parts(&parts);
    if looks_like_benign_interpreter_wait(normalized, &parts, &parsed_command_names)
        || looks_like_benign_interpreter_wait_chain(normalized, &parts)
        || looks_like_read_only_interpreter_command(normalized, &parts, &parsed_command_names)
        || looks_like_read_only_perl_filter(normalized, cwd, home_dir, ctx)
        || looks_like_safe_pytest_binary_invocation(&parts, cwd, ctx)
    {
        return false;
    }
    if contains_unsafe_pytest_binary_invocation(&parts, cwd) {
        return true;
    }
    if single_interpreter_heredoc_script(normalized).is_some()
        || parsed_command_names
            .iter()
            .any(|name| is_python_interpreter_command(name))
    {
        return !looks_like_supported_python_invocation(&parts, cwd, ctx);
    }
    if contains_unmodeled_inline_interpreter_eval(normalized, &parts, &parsed_command_names)
        || contains_destructive_node_inline_eval(&parts)
        || contains_destructive_git_command(&parts)
        || find_or_fd_uses_write_or_exec_action(&parts, home_dir)
    {
        return true;
    }
    if looks_like_safe_routine_move(&parts, cwd, home_dir, ctx) {
        return false;
    }
    if raw_command_names
        .iter()
        .chain(&parsed_command_names)
        .any(|name| DESTRUCTIVE_SHELL_COMMANDS.contains(&name.as_str()))
        || find_command_uses_delete(&parts)
        || env_split_string_payloads(&parts)
            .iter()
            .any(|payload| nested(payload, cwd, false))
        || shell_command_scripts(&parts)
            .iter()
            .any(|script| nested(script, cwd, false))
    {
        return true;
    }
    read_only_lookup_segments(&parts).iter().any(|segment| {
        segment
            .first()
            .is_some_and(|first| path_name_lower(first) == "sed")
            && segment[1..].iter().any(|part| part.starts_with("-i"))
    })
}
