//! Staged-index Git inspection recognition
//! (`runtime/git_index_inspection.py`). Git argument and configuration
//! checks stay with the resident through [`InspectionHost`].
//!
//! [`InspectionHost`]: crate::codex_output_env::InspectionHost

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_developer_graph::git_segment;
use crate::sfrs_git_cached_diff::{
    cached_diff_operands_are_safe, command_has_execution_routed_git_cached_diff,
    command_has_owned_git_cached_diff, executable_tokens, git_diff_operands,
    has_unproven_repository_selector, listed, proof_cached_diff_tokens, tokens_are_cached_diff,
};
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use crate::shell_execution_context::{
    model_shell_execution_context, ShellExecutionContext, ShellExecutionSegment,
};

const ALLOWED_CONTROLS: [&str; 5] = ["&&", "||", "|", ";", "\n"];
const RG_BOOLEAN_FLAGS: [&str; 7] = [
    "--ignore-case",
    "--line-number",
    "--no-config",
    "-i",
    "-in",
    "-n",
    "-ni",
];
const MAX_SEGMENTS: usize = 32;

/// `_static_echo_arg_is_safe`.
fn static_echo_arg_is_safe(arg: &str) -> bool {
    if ["`", "$(", "<(", ">("]
        .iter()
        .any(|marker| arg.contains(marker))
    {
        return false;
    }
    !arg.replace("$?", "").contains('$')
}

/// `_index_scan_rg_args_are_safe`.
pub(crate) fn index_scan_rg_args_are_safe(args: &[String], ctx: &Ctx) -> bool {
    let configured = ctx
        .host
        .env("RIPGREP_CONFIG_PATH")
        .is_some_and(|value| !value.is_empty());
    if configured && !args.iter().any(|arg| arg == "--no-config") {
        return false;
    }
    let mut saw_pattern = false;
    for arg in args {
        if arg.starts_with("RIPGREP_CONFIG_PATH=") {
            return false;
        }
        if listed(&RG_BOOLEAN_FLAGS, arg) {
            continue;
        }
        if arg.is_empty() || arg.starts_with('-') || saw_pattern {
            return false;
        }
        if arg.contains('$')
            || ["$(", "`", "<(", ">(", "\0"]
                .iter()
                .any(|marker| arg.contains(marker))
        {
            return false;
        }
        saw_pattern = true;
    }
    saw_pattern
}

/// `_segment_has_mutating_redirection`.
fn segment_has_mutating_redirection(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        matches!(token.as_str(), ">" | ">>" | ">|" | "1>" | "1>>" | "1>|")
            || (token.contains('>') && !token.starts_with("--"))
    })
}

fn flow_controls(controls: &[String]) -> Vec<&str> {
    controls
        .iter()
        .map(String::as_str)
        .filter(|control| *control != "\n")
        .collect()
}

/// `_git_cached_diff_segment_is_safe`.
fn git_cached_diff_segment_is_safe(
    segment: &ShellExecutionSegment,
    tokens: &[String],
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if !tokens_are_cached_diff(tokens) || has_unproven_repository_selector(tokens) {
        return false;
    }
    let Some(operands) = git_diff_operands(tokens) else {
        return false;
    };
    if !cached_diff_operands_are_safe(&operands, ctx) {
        return false;
    }
    let mut synthetic = segment.clone();
    synthetic.tokens = proof_cached_diff_tokens(tokens);
    let repository_path =
        (tokens.len() > 2 && tokens[0] == "git" && tokens[1] == "-C").then(|| tokens[2].as_str());
    let converted = git_segment(&synthetic);
    let home = home_dir.map(|path| path.to_string_lossy().into_owned());
    ctx.host.git_inspection_segment(&converted, home.as_deref())
        && ctx.host.git_show_config(&converted, repository_path)
}

/// `_context_is_low_risk_git_index_inspection`.
fn context_is_low_risk_git_index_inspection(
    context: &ShellExecutionContext,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if context.segments.is_empty() || context.segments.len() > MAX_SEGMENTS {
        return false;
    }
    if !context.complete && context.reason_code.as_deref() != Some("shell_cwd_unresolved_syntax") {
        return false;
    }
    let mut saw_cached_diff = false;
    let mut previous_was_cached_diff = false;
    for segment in &context.segments {
        if segment
            .control_before
            .iter()
            .chain(&segment.control_after)
            .any(|control| !listed(&ALLOWED_CONTROLS, control))
        {
            return false;
        }
        let Some(tokens) = executable_tokens(&segment.tokens) else {
            return false;
        };
        if tokens.is_empty() {
            previous_was_cached_diff = false;
            continue;
        }
        if segment_has_mutating_redirection(&segment.tokens) {
            return false;
        }
        let (Some(name), Some(index)) = shell_segment_primary_command(&tokens) else {
            return false;
        };
        if tokens[index].contains('/') || tokens[index].contains('\\') {
            return false;
        }
        let args = &tokens[index + 1..];
        match name.as_str() {
            "git" => {
                if !git_cached_diff_segment_is_safe(segment, &tokens, home_dir, ctx) {
                    return false;
                }
                saw_cached_diff = true;
                previous_was_cached_diff = true;
            }
            "echo" => {
                if !args.iter().all(|arg| static_echo_arg_is_safe(arg)) {
                    return false;
                }
                previous_was_cached_diff = false;
            }
            "rg" => {
                if flow_controls(&segment.control_before) != ["|"] || !previous_was_cached_diff {
                    return false;
                }
                let has_config_prefix = segment
                    .tokens
                    .iter()
                    .any(|token| token.starts_with("RIPGREP_CONFIG_PATH="));
                if has_config_prefix && !args.iter().any(|arg| arg == "--no-config") {
                    return false;
                }
                if !index_scan_rg_args_are_safe(args, ctx) {
                    return false;
                }
                previous_was_cached_diff = false;
            }
            _ => return false,
        }
    }
    saw_cached_diff
}

/// `index_inspection_execution_context`.
pub(crate) fn index_inspection_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> Option<ShellExecutionContext> {
    let execution_cwd = pyfs::resolve(&PyPath::new(&cwd?.to_string_lossy()))?;
    let execution_cwd = PathBuf::from(execution_cwd.to_string());
    let context = model_shell_execution_context(
        command_text,
        Some(&execution_cwd),
        Some(&execution_cwd),
        home_dir,
    );
    context_is_low_risk_git_index_inspection(&context, home_dir, ctx).then_some(context)
}

/// `is_low_risk_git_index_inspection`.
pub(crate) fn is_low_risk_git_index_inspection(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    index_inspection_execution_context(command_text, cwd, home_dir, ctx).is_some()
}

/// `owned_git_index_inspection_action_class`.
pub(crate) fn owned_git_index_inspection_action_class(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> Option<&'static str> {
    if !(command_text.contains("git")
        && command_text.contains("diff")
        && command_text.contains("--cached"))
    {
        return None;
    }
    let parsing_cwd: PathBuf = cwd
        .or(home_dir)
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())?;
    let context = model_shell_execution_context(
        command_text,
        Some(&parsing_cwd),
        Some(&parsing_cwd),
        home_dir,
    );
    let segments: Vec<Vec<String>> = context
        .segments
        .iter()
        .map(|segment| segment.tokens.clone())
        .collect();
    if command_has_execution_routed_git_cached_diff(&segments)
        || !command_has_owned_git_cached_diff(&segments)
    {
        return None;
    }
    if cwd.is_some() && is_low_risk_git_index_inspection(command_text, cwd, home_dir, ctx) {
        return None;
    }
    if cwd.is_some() {
        let converted: Vec<_> = context.segments.iter().map(git_segment).collect();
        let home = home_dir.map(|path| path.to_string_lossy().into_owned());
        if ctx
            .host
            .standalone_git_routine(&converted, context.complete, home.as_deref())
        {
            return None;
        }
    }
    Some("git index inspection")
}
