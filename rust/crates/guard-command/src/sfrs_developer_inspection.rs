//! Per-command read-only lookup checks used by developer inspection chains
//! (`developer_inspection.py`: the command argument rules).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, PyPath};
use crate::false_positive_rules::{
    fd_arg_requests_exec, fd_args_follow_symlinks, fd_exec_token_is_plain_sed, fd_search_targets,
    split_fd_args_and_exec,
};
use crate::sfrs_constants::{
    FIND_EXEC_ACTION_FLAGS, FIND_EXEC_PLACEHOLDER_TARGET, FIND_EXEC_TERMINATOR_TOKENS,
    READ_ONLY_SEARCH_EXECUTION_FLAGS,
};
use crate::sfrs_path_word_lookups::{
    read_only_lookup_path_word_args_are_safe, read_only_lookup_resolved_path_args_are_safe,
};
use crate::sfrs_patterns::FIND_PATH_VALUE_PREDICATES;
use crate::sfrs_read_only_filters::{
    read_only_lookup_arg_is_redirection, read_only_lookup_head_tail_args_are_safe,
    read_only_lookup_sed_args_are_safe, read_only_lookup_target_is_safe,
};
use crate::sfrs_static_safety::which_for_execution_cwd;
use crate::shell_command_wrappers::is_trusted_absolute_command_path;
use crate::shell_secret_read_support::search_operands_are_safe;

const SEARCH_FILE_INPUT_FLAGS: [&str; 3] = ["-f", "--file", "--ignore-file"];
const GREP_SHORT_VALUE_FLAGS: &[char] = &['A', 'B', 'C', 'D', 'd', 'e', 'f', 'm'];
const RG_SHORT_VALUE_FLAGS: &[char] = &[
    'A', 'B', 'C', 'E', 'M', 'T', 'd', 'e', 'f', 'g', 'j', 'm', 'r', 't',
];

fn short_value_flags(command: &str) -> &'static [char] {
    match command {
        "grep" | "egrep" | "fgrep" => GREP_SHORT_VALUE_FLAGS,
        "rg" => RG_SHORT_VALUE_FLAGS,
        _ => &[],
    }
}

/// `_read_only_lookup_primary_segment_is_safe`.
pub(crate) fn read_only_lookup_primary_segment_is_safe(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    match command {
        "sed" => read_only_lookup_sed_args_are_safe(args, true, home_dir),
        "head" | "tail" => read_only_lookup_head_tail_args_are_safe(args, true, home_dir),
        "cat" => args == [".git"] || read_only_lookup_plain_targets_are_safe(args, false, home_dir),
        "ls" => read_only_lookup_plain_targets_are_safe(args, true, home_dir),
        "basename" | "dirname" => read_only_lookup_path_word_args_are_safe(command, args),
        "readlink" | "realpath" => {
            read_only_lookup_resolved_path_args_are_safe(command, args, home_dir)
        }
        "pwd" => args.iter().all(|arg| arg == "-L" || arg == "-P"),
        "date" => read_only_lookup_date_args_are_safe(args),
        "grep" | "egrep" | "fgrep" | "rg" => {
            read_only_lookup_search_args_are_safe(command, args, home_dir, ctx)
        }
        "fd" => read_only_lookup_fd_args_are_safe(args, home_dir),
        "find" => read_only_lookup_find_args_are_safe(args, home_dir),
        _ => false,
    }
}

/// `_read_only_lookup_date_args_are_safe`.
pub(crate) fn read_only_lookup_date_args_are_safe(args: &[String]) -> bool {
    let mut saw_format = false;
    for arg in args {
        if matches!(arg.as_str(), "-u" | "--utc" | "--universal") {
            continue;
        }
        if arg.starts_with('+') && arg.chars().count() <= 256 && !arg.contains('\n') {
            if saw_format {
                return false;
            }
            saw_format = true;
            continue;
        }
        return false;
    }
    true
}

/// `_read_only_lookup_plain_targets_are_safe`.
pub(crate) fn read_only_lookup_plain_targets_are_safe(
    args: &[String],
    allow_dirs: bool,
    home_dir: Option<&Path>,
) -> bool {
    let mut targets: Vec<&str> = Vec::new();
    let mut after_options = false;
    for arg in args {
        if after_options {
            targets.push(arg);
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg == "-" {
            return false;
        }
        if arg.starts_with('-') {
            continue;
        }
        targets.push(arg);
    }
    targets
        .iter()
        .all(|target| read_only_lookup_target_is_safe(target, allow_dirs, home_dir))
}

fn file_backed_flags(command: &str) -> &'static [&'static str] {
    match command {
        "rg" => &["-f", "--file", "--ignore-file", "--config-path"],
        "grep" | "egrep" | "fgrep" => &["-f", "--file"],
        _ => &[],
    }
}

fn execution_flags(command: &str) -> &'static [&'static str] {
    READ_ONLY_SEARCH_EXECUTION_FLAGS
        .iter()
        .find(|(name, _)| *name == command)
        .map_or(&[], |(_, flags)| *flags)
}

/// `_read_only_lookup_search_args_are_safe`.
pub(crate) fn read_only_lookup_search_args_are_safe(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let option_args = args
        .iter()
        .position(|arg| arg == "--")
        .map_or(args, |at| &args[..at]);
    let configured = ctx.host.env("RIPGREP_CONFIG_PATH");
    if command == "rg"
        && configured
            .as_deref()
            .is_some_and(|value| !py_strip(value).is_empty())
        && !option_args.iter().any(|arg| arg == "--no-config")
    {
        return false;
    }
    let file_flags = file_backed_flags(command);
    let uses_file_flag = option_args.iter().any(|arg| {
        file_flags.contains(&arg.as_str())
            || file_flags
                .iter()
                .any(|flag| flag.starts_with("--") && arg.starts_with(&format!("{flag}=")))
            || file_flags
                .iter()
                .any(|flag| flag.starts_with('-') && arg.starts_with(flag) && arg != flag)
    });
    if uses_file_flag {
        return false;
    }
    let blocked = execution_flags(command);
    if args.iter().any(|arg| {
        blocked.contains(&arg.as_str())
            || blocked
                .iter()
                .any(|flag| arg.starts_with(&format!("{flag}=")))
    }) {
        return false;
    }
    if read_only_lookup_search_uses_file_input(command, args) {
        return false;
    }
    if command == "rg"
        && configured.as_deref().is_some_and(|value| !value.is_empty())
        && !ripgrep_config_is_disabled(args)
    {
        return false;
    }
    search_operands_are_safe(command, args, home_dir)
}

/// `_read_only_lookup_search_uses_file_input`.
pub(crate) fn read_only_lookup_search_uses_file_input(command: &str, args: &[String]) -> bool {
    let value_flags = short_value_flags(command);
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            break;
        }
        if SEARCH_FILE_INPUT_FLAGS.contains(&arg.as_str())
            || arg.starts_with("--file=")
            || arg.starts_with("--ignore-file=")
        {
            return true;
        }
        if !arg.starts_with('-') || arg.starts_with("--") || arg == "-" {
            continue;
        }
        let cluster: Vec<char> = arg.chars().skip(1).collect();
        for (index, flag) in cluster.iter().enumerate() {
            if *flag == 'f' {
                return true;
            }
            if value_flags.contains(flag) {
                skip_next = index == cluster.len() - 1;
                break;
            }
        }
    }
    false
}

/// `_ripgrep_config_is_disabled`.
pub(crate) fn ripgrep_config_is_disabled(args: &[String]) -> bool {
    for arg in args {
        if arg == "--" {
            return false;
        }
        if arg == "--no-config" {
            return true;
        }
    }
    false
}

/// `_read_only_lookup_fd_args_are_safe`.
pub(crate) fn read_only_lookup_fd_args_are_safe(args: &[String], home_dir: Option<&Path>) -> bool {
    if fd_args_follow_symlinks(args) {
        return false;
    }
    if args.iter().any(|arg| fd_arg_requests_exec(arg)) {
        return fd_exec_sed_read_only_args_are_safe(args, home_dir);
    }
    let Some(targets) = fd_search_targets(args) else {
        return false;
    };
    targets
        .iter()
        .all(|target| read_only_lookup_target_is_safe(target, true, home_dir))
}

/// `_fd_exec_sed_read_only_args_are_safe`.
pub(crate) fn fd_exec_sed_read_only_args_are_safe(
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    if fd_args_follow_symlinks(args) {
        return false;
    }
    let Some((fd_args, exec_parts)) = split_fd_args_and_exec(args) else {
        return false;
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
    let Some(fd_targets) = fd_search_targets(&fd_args) else {
        return false;
    };
    !fd_targets.is_empty()
        && fd_targets
            .iter()
            .all(|target| read_only_lookup_target_is_safe(target, true, home_dir))
        && read_only_lookup_sed_args_are_safe(&sed_args, false, home_dir)
}

/// `_read_only_lookup_find_args_are_safe`.
pub(crate) fn read_only_lookup_find_args_are_safe(
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    if args
        .iter()
        .any(|arg| read_only_lookup_arg_is_redirection(arg))
    {
        return false;
    }
    if find_args_use_write_or_unsafe_exec_action(args) {
        return false;
    }
    let mut leading_paths: Vec<&str> = Vec::new();
    for arg in args {
        if arg.starts_with('-') {
            break;
        }
        if !arg.is_empty() {
            leading_paths.push(arg);
        }
    }
    !leading_paths.is_empty()
        && leading_paths
            .iter()
            .all(|target| read_only_lookup_target_is_safe(target, true, home_dir))
}

/// `_find_args_use_write_or_unsafe_exec_action`.
pub(crate) fn find_args_use_write_or_unsafe_exec_action(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if FIND_PATH_VALUE_PREDICATES.contains(&arg) && index + 1 < args.len() {
            index += 2;
            continue;
        }
        if matches!(
            arg,
            "-delete" | "-fprint" | "-fprint0" | "-fprintf" | "-fls"
        ) {
            return true;
        }
        if FIND_EXEC_ACTION_FLAGS.contains(&arg) {
            if index + 1 >= args.len() {
                return true;
            }
            let command_token = args[index + 1].as_str();
            let command_name = PyPath::new(command_token).name().to_lowercase();
            let mut exec_args: Vec<String> = Vec::new();
            let mut exec_index = index + 2;
            while exec_index < args.len()
                && !FIND_EXEC_TERMINATOR_TOKENS.contains(&args[exec_index].as_str())
            {
                exec_args.push(args[exec_index].clone());
                exec_index += 1;
            }
            let is_safe_builtin = matches!(
                command_name.as_str(),
                "echo" | "printf" | "true" | "false" | "test" | "["
            );
            let is_read_only_sed =
                command_name == "sed" && find_exec_sed_args_are_read_only(&exec_args);
            let is_read_only_ls =
                command_token == "ls" && find_exec_ls_args_are_read_only(&exec_args);
            if !is_safe_builtin && !is_read_only_sed && !is_read_only_ls {
                return true;
            }
            index = if exec_index < args.len() {
                exec_index + 1
            } else {
                exec_index
            };
            continue;
        }
        index += 1;
    }
    false
}

/// `_find_exec_sed_args_are_read_only`.
pub(crate) fn find_exec_sed_args_are_read_only(args: &[String]) -> bool {
    let normalized: Vec<String> = args
        .iter()
        .map(|arg| {
            if arg == "{}" {
                FIND_EXEC_PLACEHOLDER_TARGET.to_owned()
            } else {
                arg.clone()
            }
        })
        .collect();
    read_only_lookup_sed_args_are_safe(&normalized, true, None)
}

/// `_find_exec_ls_args_are_read_only`: only options and `{}` operands.
pub(crate) fn find_exec_ls_args_are_read_only(args: &[String]) -> bool {
    let mut operands: Vec<&str> = Vec::new();
    let mut options_ended = false;
    for arg in args {
        if !options_ended && arg == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && arg.starts_with('-') {
            continue;
        }
        operands.push(arg);
    }
    !operands.is_empty() && operands.iter().all(|operand| *operand == "{}")
}

/// `_find_exec_ls_resolves_safely`.
pub(crate) fn find_exec_ls_resolves_safely(
    args: &[String],
    prefix_tokens: &[String],
    cwd: &Path,
    home_dir: &Path,
    ctx: &Ctx,
) -> bool {
    let uses_ls = args.iter().enumerate().any(|(index, arg)| {
        FIND_EXEC_ACTION_FLAGS.contains(&arg.as_str())
            && index + 1 < args.len()
            && args[index + 1] == "ls"
    });
    if !uses_ls {
        return true;
    }
    if prefix_tokens
        .iter()
        .any(|token| token == "PATH" || token.starts_with("PATH="))
    {
        return false;
    }
    let Some(found) = which_for_execution_cwd("ls", cwd, ctx) else {
        return false;
    };
    let Some(resolved) = pyfs::resolve(&PyPath::new(&found)) else {
        return false;
    };
    is_trusted_absolute_command_path(Path::new(&resolved.to_string()), Some(cwd), Some(home_dir))
}

/// `_static_shell_arg_is_safe`.
pub(crate) fn static_shell_arg_is_safe(arg: &str) -> bool {
    if ["`", "$(", "<(", ">("]
        .iter()
        .any(|marker| arg.contains(marker))
    {
        return false;
    }
    !arg.replace("$?", "").contains('$')
}

/// `_static_shell_segment_is_safe`.
pub(crate) fn static_shell_segment_is_safe(args: &[String]) -> bool {
    args.iter().all(|arg| static_shell_arg_is_safe(arg))
}
