//! Pytest configuration and module-execution safety
//! (`secret_file_request_services/pytest_config_safety.py`).
//!
//! Directories and files are probed with the same `pathlib` semantics the
//! Python reads; a probe that raises `OSError` where Python would let the
//! exception escape is treated as unsafe.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_py::{is_py_space, PyPath};
use crate::sfrs_constants::{
    PYTEST_SAFE_FLAGS, PYTEST_SAFE_FLAGS_WITH_VALUES, PYTEST_UNSAFE_ENV_KEYS,
    PYTHON_INTERPRETER_OPTIONS_WITH_VALUES, PYTHON_MODULE_MUTATING_FLAGS,
    PYTHON_MODULE_MUTATING_SUBCOMMANDS, PYTHON_MODULE_OPTIONS_WITH_VALUES,
    SAFE_PYTHON_MODULE_COMMANDS,
};
use crate::sfrs_pytest_config_search::{has_safe_value_flag_prefix, pytest_config_assessment};
use crate::sfrs_pytest_env::{
    python_module_may_be_shadowed, python_module_may_be_shadowed_in_search_roots,
    shell_segment_explicit_env_value,
};
use crate::sfrs_read_only_filters::split_attached_redirection_token;

pub(crate) const INVALID_SEARCH: &str = "../invalid-pytest-config-search";

fn lookup<'a>(table: &'a [(&str, &[&'a str])], key: &str) -> &'a [&'a str] {
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map_or(&[], |(_, values)| *values)
}

fn module_root(module: &str) -> &str {
    module.split('.').next().unwrap_or("")
}

pub(crate) fn char_len(text: &str) -> usize {
    text.chars().count()
}

/// `any(arg.startswith(option) and len(arg) > len(option) ...)`.
fn has_attached_interpreter_option(arg: &str) -> bool {
    PYTHON_INTERPRETER_OPTIONS_WITH_VALUES
        .iter()
        .any(|option| arg.starts_with(option) && char_len(arg) > char_len(option))
}

fn is_command_flag(arg: &str) -> bool {
    arg == "-c" || arg == "--command" || arg.starts_with("-c") || arg.starts_with("--command=")
}

/// `_python_module_root_from_args`.
pub(crate) fn python_module_root_from_args(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" || is_command_flag(arg) {
            return None;
        }
        if arg == "-m" {
            let module = args.get(index + 1).map_or("", String::as_str);
            let root = module_root(module);
            return (!root.is_empty()).then(|| root.to_owned());
        }
        if arg.starts_with("-m") && char_len(arg) > 2 {
            let root = module_root(&arg[2..]);
            return (!root.is_empty()).then(|| root.to_owned());
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg) {
            index += 2;
            continue;
        }
        if has_attached_interpreter_option(arg) {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            return None;
        }
        index += 1;
    }
    None
}

/// `_python_module_unsafe_env_keys`.
pub(crate) fn python_module_unsafe_env_keys(module_root: Option<&str>) -> Vec<&'static str> {
    PYTEST_UNSAFE_ENV_KEYS
        .iter()
        .copied()
        .filter(|key| module_root == Some("pytest") || *key != "PYTHONPATH")
        .collect()
}

/// `_is_shell_redirection_token`.
pub(crate) fn is_shell_redirection_token(token: &str) -> bool {
    if token == "|" || token == "|&" {
        return true;
    }
    if split_attached_redirection_token(token).is_some() {
        return true;
    }
    // `[012]?>&?\S*` fully matched.
    let rest = token
        .strip_prefix(['0', '1', '2'])
        .filter(|rest| rest.starts_with('>'))
        .unwrap_or(token);
    rest.strip_prefix('>')
        .is_some_and(|tail| !tail.chars().any(is_py_space))
}

/// `_shell_args_without_trailing_redirections`.
pub(crate) fn shell_args_without_trailing_redirections(args: &[String]) -> Vec<String> {
    let mut trimmed = args.to_vec();
    while trimmed
        .last()
        .is_some_and(|token| is_shell_redirection_token(token))
    {
        trimmed.pop();
    }
    trimmed
}

/// `_python_segment_runs_safe_module`.
pub(crate) fn python_segment_runs_safe_module(args: &[String], cwd: Option<&Path>) -> bool {
    let args = shell_args_without_trailing_redirections(args);
    if args.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" || is_command_flag(arg) {
            return false;
        }
        if arg == "-m" {
            let module = args.get(index + 1).map_or("", String::as_str);
            let rest = args.get(index + 2..).unwrap_or(&[]);
            return python_module_args_are_safe(module, rest, cwd);
        }
        if arg.starts_with("-m") && char_len(arg) > 2 {
            return python_module_args_are_safe(&arg[2..], &args[index + 1..], cwd);
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg) {
            index += 2;
            continue;
        }
        if has_attached_interpreter_option(arg) {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}

fn cwd_path(cwd: Option<&Path>) -> Option<PyPath> {
    cwd.map(|path| PyPath::new(&path.to_string_lossy()))
}

/// `_python_module_args_are_safe`.
pub(crate) fn python_module_args_are_safe(
    module: &str,
    module_args: &[String],
    cwd: Option<&Path>,
) -> bool {
    let root = module_root(module);
    if !SAFE_PYTHON_MODULE_COMMANDS.contains(&root) {
        return false;
    }
    if python_module_may_be_shadowed(root, cwd_path(cwd).as_ref()) {
        return false;
    }
    if root == "pytest" && pytest_config_may_add_unsafe_options(cwd, module_args) {
        return false;
    }
    if root == "pytest" && !pytest_module_args_are_safe(module_args) {
        return false;
    }
    let mutating_subcommands = lookup(PYTHON_MODULE_MUTATING_SUBCOMMANDS, root);
    if python_module_subcommand(root, module_args)
        .is_some_and(|subcommand| mutating_subcommands.contains(&subcommand.as_str()))
    {
        return root == "ruff" && ruff_format_target_is_bounded(module_args, cwd);
    }
    let mutating_flags = lookup(PYTHON_MODULE_MUTATING_FLAGS, root);
    !module_args.iter().any(|arg| {
        mutating_flags.contains(&arg.as_str())
            || mutating_flags.iter().any(|flag| {
                arg.strip_prefix(flag)
                    .is_some_and(|rest| rest.starts_with('='))
            })
    })
}

/// `_ruff_format_target_is_bounded`.
pub(crate) fn ruff_format_target_is_bounded(module_args: &[String], cwd: Option<&Path>) -> bool {
    let Some(cwd) = cwd else { return false };
    if module_args.len() != 2 || module_args[0] != "format" {
        return false;
    }
    let target = PyPath::new(&module_args[1]);
    if target.is_absolute()
        || target.components().iter().any(|part| part == "..")
        || module_args[1].contains('$')
        || module_args[1].contains('`')
    {
        return false;
    }
    let Ok(workspace) = std::fs::canonicalize(cwd) else {
        return false;
    };
    let Ok(resolved) = std::fs::canonicalize(workspace.join(target.to_string())) else {
        return false;
    };
    resolved.starts_with(&workspace) && resolved.is_file()
}

/// `_python_module_may_be_shadowed_from_execution_context`.
pub(crate) fn python_module_may_be_shadowed_from_execution_context(
    module_root: Option<&str>,
    cwd: Option<&Path>,
    segment: &[String],
    command_index: usize,
) -> bool {
    let Some(module_root) = module_root else {
        return true;
    };
    let mut roots: Vec<PyPath> = cwd_path(cwd).into_iter().collect();
    roots.extend(pythonpath_search_roots_from_segment(
        segment,
        command_index,
        cwd,
    ));
    python_module_may_be_shadowed_in_search_roots(module_root, &roots)
}

/// `_pythonpath_search_roots_from_segment`.
pub(crate) fn pythonpath_search_roots_from_segment(
    segment: &[String],
    command_index: usize,
    cwd: Option<&Path>,
) -> Vec<PyPath> {
    let Some(cwd) = cwd_path(cwd) else {
        return Vec::new();
    };
    let (is_set, path_value, complete) =
        shell_segment_explicit_env_value(segment, command_index, "PYTHONPATH");
    let Some(path_value) = path_value.filter(|_| complete && is_set) else {
        return Vec::new();
    };
    path_value
        .split(':')
        .map(crate::codex_output_py::py_strip)
        .filter(|entry| !entry.is_empty())
        .map(|entry| cwd.join(entry))
        .collect()
}

/// `_pytest_config_may_add_unsafe_options`.
pub(crate) fn pytest_config_may_add_unsafe_options(
    cwd: Option<&Path>,
    module_args: &[String],
) -> bool {
    match cwd {
        None => true,
        Some(cwd) => pytest_config_assessment(cwd, module_args).unsafe_options,
    }
}

/// `_pytest_module_args_are_safe`.
pub(crate) fn pytest_module_args_are_safe(module_args: &[String]) -> bool {
    let mut index = 0;
    while index < module_args.len() {
        let arg = module_args[index].as_str();
        if arg == "--" {
            return false;
        }
        if PYTEST_SAFE_FLAGS.contains(&arg) {
            index += 1;
            continue;
        }
        if PYTEST_SAFE_FLAGS_WITH_VALUES.contains(&arg) {
            index += 2;
            continue;
        }
        if has_safe_value_flag_prefix(arg) {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            return false;
        }
        index += 1;
    }
    true
}

/// `_python_module_subcommand`.
pub(crate) fn python_module_subcommand(
    module_root: &str,
    module_args: &[String],
) -> Option<String> {
    let options = lookup(PYTHON_MODULE_OPTIONS_WITH_VALUES, module_root);
    let mut index = 0;
    while index < module_args.len() {
        let arg = module_args[index].as_str();
        if arg == "--" {
            return None;
        }
        if options.contains(&arg) {
            index += 2;
            continue;
        }
        if options.iter().any(|option| {
            arg.strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='))
        }) {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(arg.to_owned());
    }
    None
}
