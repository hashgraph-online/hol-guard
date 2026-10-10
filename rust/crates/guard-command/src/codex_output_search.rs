//! Search (`rg`/`grep`/`fd`/`git grep`) target parsing and source-likeness for
//! the Codex tool-output review.

use std::collections::HashSet;

use crate::codex_output_args::{parse_sed_args, sed_script_is_bounded_print};
use crate::codex_output_env::Ctx;
use crate::codex_output_py::PyPath;
use crate::codex_output_source_paths::source_path_is_allowed;
use crate::false_positive_rules::{
    fd_arg_requests_exec, fd_args_follow_symlinks, fd_exec_token_is_plain_sed, fd_search_targets,
    split_fd_args_and_exec,
};

/// The per-command policy scope: working directory, explicit home and process
/// facts.
#[derive(Clone, Copy)]
pub(crate) struct Scope<'a> {
    pub(crate) cwd: Option<&'a PyPath>,
    pub(crate) home: Option<&'a PyPath>,
    pub(crate) ctx: &'a Ctx<'a>,
}

impl<'a> Scope<'a> {
    pub(crate) fn without_home(self) -> Self {
        Self { home: None, ..self }
    }
}

const SEARCH_PATTERN_VALUE_FLAGS: &[&str] = &["-e", "--regexp", "-f", "--file"];
const SEARCH_OPTION_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--regexp",
    "-f",
    "--file",
    "-g",
    "--glob",
    "--iglob",
    "--max-depth",
    "--type",
    "-t",
    "--type-not",
];
const SEARCH_UNSAFE_FLAGS: &[&str] = &["--dereference-recursive", "--follow", "--pre"];

fn executable_option_value_flags(executable: &str) -> &'static [&'static str] {
    match executable {
        "grep" => &["-d", "--directories"],
        "rg" => &["-T"],
        _ => &[],
    }
}

fn unsafe_short_flags(executable: &str) -> &'static [char] {
    match executable {
        "egrep" | "fgrep" | "grep" => &['R'],
        "rg" => &['L'],
        _ => &[],
    }
}

/// `_git_grep_uses_external_execution`.
pub(crate) fn git_grep_uses_external_execution(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "-O"
            || (arg.starts_with("-O") && arg.chars().count() > 2)
            || arg == "--open-files-in-pager"
            || arg.starts_with("--open-files-in-pager=")
            || arg == "--textconv"
            || arg == "--ext-grep"
    })
}

/// `_shell_wrapper_script_index`.
pub(crate) fn shell_wrapper_script_index(parts: &[String]) -> Option<usize> {
    for (offset, arg) in parts.iter().enumerate().skip(1) {
        if arg == "-c" {
            return Some(offset + 1);
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c') {
            return Some(offset + 1);
        }
    }
    None
}

/// `_codex_command_has_unquoted_shell_control`.
pub(crate) fn has_unquoted_shell_control(command: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in command.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            if quote == Some('"') && (c == '`' || c == '$') {
                return true;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            continue;
        }
        if matches!(c, '\n' | '\r' | '|' | '&' | ';' | '>' | '<' | '`' | '$') {
            return true;
        }
    }
    false
}

fn arg_is_unsafe(arg: &str, executable: &str, option_value_flags: &HashSet<&str>) -> bool {
    if SEARCH_UNSAFE_FLAGS.contains(&arg)
        || SEARCH_UNSAFE_FLAGS
            .iter()
            .any(|flag| arg.starts_with(&format!("{flag}=")))
    {
        return true;
    }
    if !arg.starts_with('-') || arg.starts_with("--") {
        return false;
    }
    let unsafe_flags = unsafe_short_flags(executable);
    for flag in arg[1..].chars() {
        if unsafe_flags.contains(&flag) {
            return true;
        }
        if option_value_flags.contains(format!("-{flag}").as_str()) {
            return false;
        }
    }
    false
}

/// `_codex_search_targets`.
pub(crate) fn search_targets(args: &[String], executable: &str) -> Vec<String> {
    let option_value_flags: HashSet<&str> = SEARCH_OPTION_VALUE_FLAGS
        .iter()
        .chain(executable_option_value_flags(executable).iter())
        .copied()
        .collect();
    let mut positional = Vec::new();
    let mut skip_next = false;
    let mut pattern_from_option = false;
    let mut after_terminator = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if after_terminator {
            positional.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_terminator = true;
            continue;
        }
        if arg_is_unsafe(arg, executable, &option_value_flags) {
            return Vec::new();
        }
        if SEARCH_PATTERN_VALUE_FLAGS.contains(&arg.as_str()) {
            pattern_from_option = true;
            skip_next = true;
            continue;
        }
        if ["-e", "-f"]
            .iter()
            .any(|flag| arg.starts_with(flag) && arg.chars().count() > flag.chars().count())
        {
            pattern_from_option = true;
            continue;
        }
        if option_value_flags.contains(arg.as_str()) {
            skip_next = true;
            continue;
        }
        if SEARCH_PATTERN_VALUE_FLAGS
            .iter()
            .any(|flag| arg.starts_with(&format!("{flag}=")))
        {
            pattern_from_option = true;
            continue;
        }
        if option_value_flags
            .iter()
            .any(|flag| arg.starts_with(&format!("{flag}=")))
        {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        positional.push(arg.clone());
    }
    if pattern_from_option {
        return positional;
    }
    if positional.len() >= 2 {
        return positional[1..].to_vec();
    }
    Vec::new()
}

/// `_codex_grep_args_request_recursive_search`.
fn grep_args_request_recursive_search(args: &[String]) -> bool {
    let mut skip_next = false;
    for (index, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            return false;
        }
        if SEARCH_PATTERN_VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if ["-e", "-f"]
            .iter()
            .any(|flag| arg.starts_with(flag) && arg.chars().count() > flag.chars().count())
        {
            continue;
        }
        if arg == "--dereference-recursive" || arg == "--recursive" {
            return true;
        }
        let allowed_directory = |value: &str| matches!(value, "read" | "skip");
        if arg == "-d" || arg == "--directories" {
            if args
                .get(index + 1)
                .is_none_or(|next| !allowed_directory(next))
            {
                return true;
            }
            skip_next = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--directories=") {
            if !allowed_directory(value) {
                return true;
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("-d") {
            if !allowed_directory(value) {
                return true;
            }
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('r') {
            return true;
        }
    }
    false
}

/// `_codex_search_target_is_source_like`.
pub(crate) fn target_is_source_like(target: &str, scope: Scope, allow_external: bool) -> bool {
    source_path_is_allowed(target, scope.cwd, scope.home, scope.ctx, allow_external).allowed
}

/// `_codex_search_target_is_external_source_like`.
pub(crate) fn target_is_external_source_like(target: &str, scope: Scope) -> bool {
    source_path_is_allowed(target, scope.cwd, scope.home, scope.ctx, true).reason_code
        == "external_source_path"
}

/// `_codex_search_targets_are_source_like`.
pub(crate) fn search_targets_are_source_like(
    args: &[String],
    scope: Scope,
    executable: &str,
) -> bool {
    let targets = search_targets(args, executable);
    if targets.is_empty() {
        return false;
    }
    let allow_external = executable == "grep";
    let decisions: Vec<_> = targets
        .iter()
        .map(|target| {
            source_path_is_allowed(target, scope.cwd, scope.home, scope.ctx, allow_external)
        })
        .collect();
    if !decisions.iter().all(|decision| decision.allowed) {
        return false;
    }
    let has_external = decisions
        .iter()
        .any(|decision| decision.reason_code == "external_source_path");
    !(has_external && executable == "grep" && grep_args_request_recursive_search(args))
}

/// `_codex_fd_targets`.
pub(crate) fn fd_targets(args: &[String]) -> Vec<String> {
    match fd_search_targets(args) {
        Some(targets) if !targets.is_empty() => targets,
        _ => vec!["__guard_unsafe_fd_args__".to_owned()],
    }
}

/// `_codex_fd_targets_are_source_like`.
pub(crate) fn fd_targets_are_source_like(args: &[String], scope: Scope) -> bool {
    if fd_args_follow_symlinks(args) {
        return false;
    }
    let targets = fd_targets(args);
    !targets.is_empty()
        && targets
            .iter()
            .all(|target| target_is_source_like(target, scope, false))
}

/// `_codex_fd_exec_is_bounded_read_only`.
pub(crate) fn fd_exec_is_bounded_read_only(args: &[String]) -> bool {
    if fd_args_follow_symlinks(args) {
        return false;
    }
    let Some((_fd_args, exec_parts)) = split_fd_args_and_exec(args) else {
        return !args.iter().any(|arg| fd_arg_requests_exec(arg));
    };
    if exec_parts.is_empty() || !fd_exec_token_is_plain_sed(&exec_parts[0]) {
        return false;
    }
    if exec_parts.iter().filter(|part| *part == "{}").count() != 1 {
        return false;
    }
    let sed_args: Vec<String> = exec_parts[1..]
        .iter()
        .filter(|arg| *arg != "{}")
        .cloned()
        .collect();
    sed_args_are_bounded_filter(&sed_args)
}

/// `_codex_sed_args_are_bounded_filter`.
pub(crate) fn sed_args_are_bounded_filter(args: &[String]) -> bool {
    let Some(parsed) = parse_sed_args(args) else {
        return false;
    };
    parsed.targets.is_empty()
        && parsed.saw_print_suppression
        && parsed
            .scripts
            .iter()
            .all(|script| sed_script_is_bounded_print(script))
}
