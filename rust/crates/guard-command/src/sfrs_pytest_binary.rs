//! Pytest binary and environment-wrapper safety
//! (`secret_file_request_services/pytest_binary_safety.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_py::{py_strip, PyPath};
use crate::sfrs_constants::{
    PYTEST_UNSAFE_ENV_KEYS, PYTHON_INTERPRETER_OPTIONS_WITH_VALUES, READ_ONLY_LOOKUP_FILTERS,
    SAFE_STATIC_SHELL_COMMANDS,
};
use crate::sfrs_developer_inspection::static_shell_segment_is_safe;
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_pytest_config_safety::{
    pytest_config_may_add_unsafe_options, pytest_module_args_are_safe,
    python_module_may_be_shadowed_from_execution_context, python_module_root_from_args,
    python_module_unsafe_env_keys, python_segment_runs_safe_module,
    shell_args_without_trailing_redirections,
};
use crate::sfrs_pytest_env::{
    python_module_may_be_shadowed, shell_env_assignment_key, shell_segment_sets_env_key,
};
use crate::sfrs_pytest_target::segment_targets_pytest;
use crate::sfrs_pytest_wrappers::{
    shell_directory_setup_segment_is_safe, shell_segment_uses_cwd_changing_wrapper,
    shell_segment_uses_env_split_string_wrapper,
};
use crate::sfrs_read_only_filters::read_only_lookup_filter_segment_is_safe;
use crate::sfrs_selectors::python_segment_targets_module;
use crate::sfrs_shell_tokens::{iter_shell_command_segments, shell_segment_primary_command};
use crate::sfrs_shlex::{split_with, PLAIN_LEXER};
use crate::sfrs_static_safety::shell_token_has_command_substitution;
use crate::shell_structure::extract_heredocs;

/// `_is_literal_cat_heredoc_to_stdout`.
pub(crate) fn is_literal_cat_heredoc_to_stdout(command_text: &str) -> bool {
    let heredocs = extract_heredocs(command_text);
    let [heredoc] = heredocs.as_slice() else {
        return false;
    };
    if !py_strip(&command_text[heredoc.end..]).is_empty() {
        return false;
    }
    let line_start = command_text[..heredoc.operator_start]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    let header = format!(
        "{}{}",
        &command_text[line_start..heredoc.operator_start],
        &command_text[heredoc.declaration_end..heredoc.body_start]
    );
    match split_with(PLAIN_LEXER, &header) {
        Ok(tokens) => tokens == ["cat"] || tokens == ["cat", "-"],
        Err(_) => false,
    }
}

/// The primary command of every segment, or `None` when one has none.
fn segment_commands(parts: &[String]) -> Option<Vec<(Vec<String>, String, usize)>> {
    iter_shell_command_segments(parts)
        .into_iter()
        .map(|segment| match shell_segment_primary_command(&segment) {
            (Some(name), Some(index)) => Some((segment, name, index)),
            _ => None,
        })
        .collect()
}

/// A segment a safe-invocation scan may skip.
fn is_safe_filler_segment(command_name: &str, segment_args: &[String], ctx: &Ctx) -> bool {
    shell_directory_setup_segment_is_safe(command_name, segment_args)
        || (READ_ONLY_LOOKUP_FILTERS.contains(&command_name)
            && read_only_lookup_filter_segment_is_safe(
                command_name,
                segment_args,
                None,
                false,
                ctx,
            ))
        || (SAFE_STATIC_SHELL_COMMANDS.contains(&command_name)
            && static_shell_segment_is_safe(segment_args))
}

/// `_looks_like_safe_python_module_invocation`.
pub(crate) fn looks_like_safe_python_module_invocation(
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let segments = iter_shell_command_segments(parts);
    if segments.is_empty() {
        return false;
    }
    let mut saw_python_module = false;
    for segment in &segments {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment)
        else {
            return false;
        };
        let segment_args = &segment[command_index + 1..];
        if is_python_interpreter_command(&command_name) {
            let module_root = python_module_root_from_args(segment_args);
            let unsafe_keys = python_module_unsafe_env_keys(module_root.as_deref());
            if unsafe_keys
                .iter()
                .any(|key| shell_segment_sets_env_key(segment, command_index, key))
                || shell_segment_uses_env_split_string_wrapper(segment, command_index)
                || shell_segment_uses_cwd_changing_wrapper(segment, command_index)
                || python_module_may_be_shadowed_from_execution_context(
                    module_root.as_deref(),
                    cwd,
                    segment,
                    command_index,
                )
                || !python_segment_runs_safe_module(segment_args, cwd)
            {
                return false;
            }
            saw_python_module = true;
            continue;
        }
        if is_safe_filler_segment(&command_name, segment_args, ctx) {
            continue;
        }
        return false;
    }
    saw_python_module
}

/// `_looks_like_bounded_python_script_invocation`.
pub(crate) fn looks_like_bounded_python_script_invocation(
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let Some(cwd) = cwd else { return false };
    let Some(segments) = segment_commands(parts) else {
        return false;
    };
    if segments.is_empty() {
        return false;
    }
    let mut saw_script = false;
    for (segment, command_name, command_index) in &segments {
        let segment_args = &segment[command_index + 1..];
        if is_python_interpreter_command(command_name) {
            if saw_script || bounded_python_script_path(segment_args, cwd, ctx).is_none() {
                return false;
            }
            saw_script = true;
            continue;
        }
        if shell_directory_setup_segment_is_safe(command_name, segment_args) {
            continue;
        }
        return false;
    }
    saw_script
}

/// `_looks_like_supported_python_invocation`.
pub(crate) fn looks_like_supported_python_invocation(
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    looks_like_bounded_python_script_invocation(parts, cwd, ctx)
        || looks_like_safe_python_module_invocation(parts, cwd, ctx)
}

/// `Path(operand).expanduser()` with the caller's `HOME`; a user-name home is
/// not looked up and leaves the operand relative, which the caller then rejects.
fn expand_user(operand: &str, ctx: &Ctx) -> PathBuf {
    if operand == "~" || operand.starts_with("~/") {
        if let Some(home) = ctx.host.env("HOME").filter(|home| !home.is_empty()) {
            let rest = operand[1..].trim_start_matches('/');
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(operand)
}

/// `_bounded_python_script_path`.
pub(crate) fn bounded_python_script_path(
    args: &[String],
    cwd: &Path,
    ctx: &Ctx,
) -> Option<PathBuf> {
    let args = shell_args_without_trailing_redirections(args);
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            index += 1;
            break;
        }
        if matches!(arg, "-c" | "--command" | "-m")
            || arg.starts_with("-c")
            || arg.starts_with("--command=")
            || arg.starts_with("-m")
        {
            return None;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg) {
            index += 2;
            continue;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES
            .iter()
            .any(|option| arg.starts_with(option) && arg.chars().count() > option.chars().count())
        {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    let operand = args.get(index)?;
    if operand == "-" || !operand.ends_with(".py") || shell_token_has_command_substitution(operand)
    {
        return None;
    }
    let mut candidate = expand_user(operand, ctx);
    if !candidate.is_absolute() {
        candidate = cwd.join(candidate);
    }
    let resolved = std::fs::canonicalize(&candidate).ok()?;
    let root = std::fs::canonicalize(cwd).ok()?;
    if !resolved.starts_with(&root) {
        return None;
    }
    resolved.is_file().then_some(resolved)
}

/// `_contains_unsafe_pytest_environment_wrapper`. Both Python branches under a
/// cwd-changing wrapper return `True`, so the safety probes are not repeated.
pub(crate) fn contains_unsafe_pytest_environment_wrapper(parts: &[String]) -> bool {
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if !shell_segment_uses_cwd_changing_wrapper(&segment, command_index) {
            continue;
        }
        if command_name == "pytest" {
            return true;
        }
        if is_python_interpreter_command(&command_name)
            && python_segment_targets_module(&segment[command_index + 1..], "pytest")
        {
            return true;
        }
    }
    false
}

/// `_contains_pytest_process_substitution`.
pub(crate) fn contains_pytest_process_substitution(command_text: &str, parts: &[String]) -> bool {
    if !command_text.contains("<(") && !command_text.contains(">(") {
        return false;
    }
    iter_shell_command_segments(parts).iter().any(|segment| {
        matches!(
            shell_segment_primary_command(segment),
            (Some(name), Some(index)) if segment_targets_pytest(segment, &name, index, 0)
        )
    })
}

fn is_tracked_env_key(key: &str) -> bool {
    key == "PATH" || PYTEST_UNSAFE_ENV_KEYS.contains(&key)
}

/// `_contains_prior_pytest_state_mutation`.
pub(crate) fn contains_prior_pytest_state_mutation(parts: &[String]) -> bool {
    let mut saw_state_mutation = false;
    let mut exported: Vec<String> = Vec::new();
    for segment in iter_shell_command_segments(parts) {
        if segment.iter().any(|token| {
            shell_env_assignment_key(token)
                .is_some_and(|key| key == "PATH" || exported.contains(&key))
        }) {
            saw_state_mutation = true;
        }
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if segment_targets_pytest(&segment, &command_name, command_index, 0) {
            return saw_state_mutation;
        }
        let args = &segment[command_index + 1..];
        match command_name.as_str() {
            "cd" | "pushd" | "popd" => {
                if !shell_directory_setup_segment_is_safe(&command_name, args) {
                    saw_state_mutation = true;
                }
                continue;
            }
            "set" if shell_set_exports_assignments(args) => {
                saw_state_mutation = true;
                continue;
            }
            "export" => {
                record_exports(args, false, &mut exported, &mut saw_state_mutation);
            }
            "declare" | "typeset" if shell_declaration_exports_env(args) => {
                record_exports(args, true, &mut exported, &mut saw_state_mutation);
            }
            _ => {}
        }
    }
    false
}

fn record_exports(
    args: &[String],
    skip_flags: bool,
    exported: &mut Vec<String>,
    saw_state_mutation: &mut bool,
) {
    for token in args {
        if skip_flags && (token.starts_with('-') || token == "--") {
            continue;
        }
        let key = shell_declared_env_key(token);
        if !is_tracked_env_key(&key) {
            continue;
        }
        if !exported.contains(&key) {
            exported.push(key);
        }
        if token.contains('=') {
            *saw_state_mutation = true;
        }
    }
}

/// `_shell_declared_env_key`.
pub(crate) fn shell_declared_env_key(token: &str) -> String {
    shell_env_assignment_key(token).unwrap_or_else(|| token.to_uppercase())
}

/// `_shell_declaration_exports_env`.
pub(crate) fn shell_declaration_exports_env(args: &[String]) -> bool {
    for token in args {
        if token == "--" {
            return false;
        }
        if !token.starts_with('-') {
            continue;
        }
        if token.trim_start_matches('-').contains('x') {
            return true;
        }
    }
    false
}

/// `_shell_set_exports_assignments`.
pub(crate) fn shell_set_exports_assignments(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "--" {
            return false;
        }
        if matches!(token, "-a" | "-k" | "allexport" | "keyword") {
            return true;
        }
        if token == "-o" {
            return args
                .get(index + 1)
                .is_some_and(|next| next == "allexport" || next == "keyword");
        }
        if token == "+o" {
            index += 2;
            continue;
        }
        if token.starts_with('-')
            && !token.starts_with("--")
            && token.chars().skip(1).any(|flag| flag == 'a' || flag == 'k')
        {
            return true;
        }
        index += 1;
    }
    false
}

/// `_looks_like_safe_pytest_binary_invocation`.
pub(crate) fn looks_like_safe_pytest_binary_invocation(
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let mut saw_pytest = false;
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            return false;
        };
        let segment_args = &segment[command_index + 1..];
        if command_name == "pytest" {
            if shell_segment_sets_env_key(&segment, command_index, "PATH")
                || PYTEST_UNSAFE_ENV_KEYS
                    .iter()
                    .any(|key| shell_segment_sets_env_key(&segment, command_index, key))
                || shell_segment_uses_env_split_string_wrapper(&segment, command_index)
                || shell_segment_uses_cwd_changing_wrapper(&segment, command_index)
                || !pytest_binary_segment_is_safe(&segment[command_index], segment_args, cwd)
            {
                return false;
            }
            saw_pytest = true;
            continue;
        }
        if is_safe_filler_segment(&command_name, segment_args, ctx) {
            continue;
        }
        return false;
    }
    saw_pytest
}

/// `_pytest_binary_segment_is_safe`.
pub(crate) fn pytest_binary_segment_is_safe(
    command_token: &str,
    module_args: &[String],
    cwd: Option<&Path>,
) -> bool {
    if command_token.contains('/') || command_token.contains('\\') {
        return false;
    }
    let cwd_path = cwd.map(|path| PyPath::new(&path.to_string_lossy()));
    if python_module_may_be_shadowed("pytest", cwd_path.as_ref()) {
        return false;
    }
    if pytest_config_may_add_unsafe_options(cwd, module_args) {
        return false;
    }
    pytest_module_args_are_safe(module_args)
}
