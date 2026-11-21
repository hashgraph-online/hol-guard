//! Read-only interpreter and observer recognition
//! (`interpreter_observers.py`). The environment and module-shadow probes of
//! that module live in `sfrs_pytest_env`.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
use crate::sfrs_constants::{
    PYTEST_UNSAFE_ENV_KEYS, PYTHON_INTERPRETER_OPTIONS_WITH_VALUES, READ_ONLY_LOOKUP_COMMANDS,
    READ_ONLY_LOOKUP_FILTERS, SAFE_SHELL_REDIRECT_TARGETS, SAFE_STATIC_SHELL_COMMANDS,
    SHELL_COMMAND_STRING_INTERPRETERS, SHELL_STARTUP_ENV_KEYS,
};
use crate::sfrs_developer_inspection::{
    read_only_lookup_primary_segment_is_safe, ripgrep_config_is_disabled,
    static_shell_segment_is_safe,
};
use crate::sfrs_interpreter_heredoc::{
    is_read_only_observer_interpreter_command, normalized_redirect_target, shell_heredoc_payloads,
    shell_script_targets_pytest, single_interpreter_heredoc_args,
    single_interpreter_heredoc_interpreter, single_interpreter_heredoc_script,
};
use crate::sfrs_interpreter_scripts::{
    is_python_interpreter_command, is_script_interpreter_command, script_interpreter_texts,
    script_is_benign_wait, script_is_read_only_observer,
};
use crate::sfrs_pytest_env::{shell_env_assignment_key, shell_segment_sets_env_key};
use crate::sfrs_read_only_filters::{
    read_only_lookup_filter_segment_is_safe, split_attached_redirection_token,
};
use crate::sfrs_shell_tokens::{iter_shell_command_segments, shell_segment_primary_command};
use crate::shell_secret_read_support::{
    ripgrep_args_expand_hidden_files, shell_interpreter_command_payload,
};

fn has_substitution_marker(command_text: &str) -> bool {
    ["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| command_text.contains(marker))
}

/// `_looks_like_safe_read_only_lookup_command`.
pub(crate) fn looks_like_safe_read_only_lookup_command(
    command_text: &str,
    parts: &[String],
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if has_substitution_marker(command_text) {
        return false;
    }
    if parts
        .iter()
        .any(|token| matches!(token.as_str(), ";" | "&" | "||" | "|&"))
    {
        return false;
    }
    let segments = read_only_lookup_segments(parts);
    if segments.is_empty() {
        return false;
    }
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return false;
        }
        let (Some(command), Some(command_index)) = shell_segment_primary_command(segment) else {
            return false;
        };
        let command_token = &segment[command_index];
        let args = &segment[command_index + 1..];
        if command_token.contains('/') || command_token.contains('\\') {
            return false;
        }
        if command_index > 0 {
            let config_prefix_only = segment[..command_index].iter().all(|token| {
                shell_env_assignment_key(token).as_deref() == Some("RIPGREP_CONFIG_PATH")
            });
            if index != 0
                || command != "rg"
                || !ripgrep_config_is_disabled(args)
                || !config_prefix_only
            {
                return false;
            }
        }
        if index > 0 && !READ_ONLY_LOOKUP_FILTERS.contains(&command.as_str()) {
            return false;
        }
        if index == 0 {
            if !READ_ONLY_LOOKUP_COMMANDS.contains(&command.as_str()) {
                return false;
            }
            if command == "rg" && ripgrep_args_expand_hidden_files(args) {
                return false;
            }
            if !read_only_lookup_primary_segment_is_safe(&command, args, home_dir, ctx) {
                return false;
            }
        } else if !read_only_lookup_filter_segment_is_safe(&command, args, home_dir, false, ctx) {
            return false;
        }
    }
    true
}

/// `_read_only_lookup_segments`.
pub(crate) fn read_only_lookup_segments(parts: &[String]) -> Vec<Vec<String>> {
    let mut segments: Vec<Vec<String>> = vec![Vec::new()];
    for token in parts {
        if token == "|" || token == "&&" {
            if segments.last().is_some_and(Vec::is_empty) {
                return Vec::new();
            }
            segments.push(Vec::new());
            continue;
        }
        let normalized = py_strip(token);
        if normalized.is_empty() {
            continue;
        }
        if read_only_lookup_token_is_safe_stderr_discard(normalized) {
            continue;
        }
        if split_attached_redirection_token(normalized).is_some() {
            return Vec::new();
        }
        if let Some(last) = segments.last_mut() {
            last.push(normalized.to_owned());
        }
    }
    segments
        .into_iter()
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// `_read_only_lookup_token_is_safe_stderr_discard`.
pub(crate) fn read_only_lookup_token_is_safe_stderr_discard(token: &str) -> bool {
    let Some((prefix, fd, _op, target)) = split_attached_redirection_token(token) else {
        return false;
    };
    prefix.is_empty()
        && fd == "2"
        && SAFE_SHELL_REDIRECT_TARGETS
            .contains(&normalized_redirect_target(&target).to_lowercase().as_str())
}

/// `_contains_pytest_env_shell_script_wrapper`.
pub(crate) fn contains_pytest_env_shell_script_wrapper(parts: &[String]) -> bool {
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if !SHELL_COMMAND_STRING_INTERPRETERS.contains(&command_name.as_str()) {
            continue;
        }
        let has_unsafe_env = PYTEST_UNSAFE_ENV_KEYS
            .iter()
            .chain(SHELL_STARTUP_ENV_KEYS.iter())
            .any(|key| shell_segment_sets_env_key(&segment, command_index, key));
        if !has_unsafe_env {
            continue;
        }
        if let Some(payload) = shell_interpreter_command_payload(&segment, command_index) {
            if shell_script_targets_pytest(&payload.script_text) {
                return true;
            }
        }
    }
    false
}

/// `_looks_like_benign_interpreter_wait`.
pub(crate) fn looks_like_benign_interpreter_wait(
    command_text: &str,
    parts: &[String],
    command_names: &[String],
) -> bool {
    if has_substitution_marker(command_text) {
        return false;
    }
    if command_names.is_empty()
        || !command_names
            .iter()
            .all(|name| is_script_interpreter_command(name))
    {
        return false;
    }
    let scripts = script_interpreter_texts(parts);
    if scripts.is_empty() || scripts.len() != command_names.len() {
        return false;
    }
    scripts.iter().all(|script| script_is_benign_wait(script))
}

/// `_looks_like_benign_interpreter_wait_chain`.
pub(crate) fn looks_like_benign_interpreter_wait_chain(
    command_text: &str,
    parts: &[String],
) -> bool {
    if has_substitution_marker(command_text) {
        return false;
    }
    if parts
        .iter()
        .any(|token| matches!(token.as_str(), ";" | "&" | "||" | "|" | "|&"))
    {
        return false;
    }
    let mut saw_wait = false;
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            return false;
        };
        let args = &segment[command_index + 1..];
        if is_script_interpreter_command(&command_name) {
            let scripts = script_interpreter_texts(&segment);
            if scripts.len() != 1 || !script_is_benign_wait(&scripts[0]) {
                return false;
            }
            saw_wait = true;
            continue;
        }
        if SAFE_STATIC_SHELL_COMMANDS.contains(&command_name.as_str())
            && static_shell_segment_is_safe(args)
        {
            continue;
        }
        return false;
    }
    saw_wait
}

/// `_looks_like_read_only_interpreter_compound`.
pub(crate) fn looks_like_read_only_interpreter_compound(
    command_text: &str,
    parts: &[String],
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if has_substitution_marker(command_text) {
        return false;
    }
    let segments = iter_shell_command_segments(parts);
    if segments.len() < 2 {
        return false;
    }
    let mut saw_interpreter = false;
    for segment in &segments {
        let (Some(command_name), Some(_)) = shell_segment_primary_command(segment) else {
            return false;
        };
        if is_python_interpreter_command(&command_name) {
            let scripts = script_interpreter_texts(segment);
            if scripts.len() != 1 || !script_is_read_only_observer(&scripts[0]) {
                return false;
            }
            saw_interpreter = true;
            continue;
        }
        let segment_text = segment.join(" ");
        if !looks_like_safe_read_only_lookup_command(&segment_text, segment, home_dir, ctx) {
            return false;
        }
    }
    saw_interpreter
}

/// `_looks_like_read_only_interpreter_command`.
pub(crate) fn looks_like_read_only_interpreter_command(
    command_text: &str,
    parts: &[String],
    command_names: &[String],
) -> bool {
    if has_substitution_marker(command_text) {
        return false;
    }
    if command_names
        .iter()
        .any(|name| is_python_interpreter_command(name))
        && parts_use_python_module_mode(parts)
    {
        return false;
    }
    if let Some(heredoc_script) = single_interpreter_heredoc_script(command_text) {
        let Some(interpreter) = single_interpreter_heredoc_interpreter(command_text) else {
            return false;
        };
        if !is_read_only_observer_interpreter_command(&interpreter) {
            return false;
        }
        let heredoc_args = single_interpreter_heredoc_args(command_text);
        if !matches!(heredoc_args.as_deref(), Some("") | Some("-")) {
            return false;
        }
        let mut scripts = script_interpreter_texts(parts);
        if !scripts.is_empty() {
            scripts.push(heredoc_script);
            return scripts
                .iter()
                .all(|script| script_is_read_only_observer(script));
        }
        return script_is_read_only_observer(&heredoc_script);
    }
    if command_names.is_empty()
        || !command_names
            .iter()
            .all(|name| is_read_only_observer_interpreter_command(name))
    {
        return false;
    }
    let mut scripts = script_interpreter_texts(parts);
    scripts.extend(shell_heredoc_payloads(command_text));
    if scripts.is_empty() || scripts.len() != command_names.len() {
        return false;
    }
    scripts
        .iter()
        .all(|script| script_is_read_only_observer(script))
}

/// `_parts_use_python_module_mode`.
pub(crate) fn parts_use_python_module_mode(parts: &[String]) -> bool {
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if !is_python_interpreter_command(&command_name) {
            continue;
        }
        if python_args_use_module_mode(&segment[command_index + 1..]) {
            return true;
        }
    }
    false
}

/// `_python_args_use_module_mode`.
pub(crate) fn python_args_use_module_mode(args: &[String]) -> bool {
    const CLUSTERABLE_FLAGS: &str = "bBdEhiIOPqRsSuvV";
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--"
            || arg == "-c"
            || arg == "--command"
            || arg.starts_with("-c")
            || arg.starts_with("--command=")
        {
            return false;
        }
        if arg == "-m" || (arg.starts_with("-m") && arg.chars().count() > 2) {
            return true;
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
        if arg.starts_with('-') && !arg.starts_with("--") {
            let chars: Vec<char> = arg.chars().collect();
            if let Some(module_index) = chars
                .iter()
                .skip(1)
                .position(|c| *c == 'm')
                .map(|at| at + 1)
            {
                if chars[1..module_index]
                    .iter()
                    .all(|flag| CLUSTERABLE_FLAGS.contains(*flag))
                {
                    return true;
                }
            }
        }
        if !arg.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}
