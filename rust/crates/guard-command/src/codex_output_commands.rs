//! Command-level reviews for Codex tool-output: local-content reads, the
//! environment-dump pipeline, focused pytest verification and read-only git
//! metadata.

use crate::codex_output_args::git_grep_search_args;
use crate::codex_output_env::GitCheck;
use crate::codex_output_fs as pyfs;
use crate::codex_output_inspection::{is_read_only_source_search, is_read_only_source_view};
use crate::codex_output_py::{shlex_join, shlex_split};
use crate::codex_output_search::Scope;
use crate::codex_output_shlex::shell_split;
use crate::codex_output_splitters::split_pipeline;
use crate::codex_output_wrappers::{
    command_segment_parts, command_start_indexes, executable_name_lower,
    parts_are_environment_dump, unwrapped_command_parts,
};

const LOCAL_READ_COMMANDS: &[&str] =
    &["cat", "grep", "head", "nl", "rg", "sed", "tail", "wc", "yq"];
const PYTEST_SAFE_FLAGS: &[&str] = &["-q", "-s", "-x", "-v", "-vv", "-vvv", "-ra", "--lf", "--ff"];
const PYTEST_SAFE_FLAGS_WITH_VALUES: &[&str] =
    &["-k", "-m", "--maxfail", "--tb", "--color", "--durations"];
const PYTEST_SAFE_FLAG_PREFIXES: &[&str] = &["--maxfail=", "--tb=", "--color=", "--durations="];
const SAFE_SHELL_REDIRECTION_TOKENS: &[&str] =
    &["1>&2", "2>&1", ">/dev/null", "1>/dev/null", "2>/dev/null"];

fn search_or_view(segment: &str, scope: Scope) -> bool {
    let scope = scope.without_home();
    is_read_only_source_search(segment, scope) || is_read_only_source_view(segment, scope)
}

fn sequence_is_read_only_source_inspection(parts: &[String], scope: Scope) -> bool {
    let command_parts = unwrapped_command_parts(parts);
    !command_parts.is_empty() && search_or_view(&shlex_join(&command_parts), scope)
}

fn parts_are_git_grep(parts: &[String]) -> bool {
    parts
        .first()
        .is_some_and(|first| executable_name_lower(first) == "git")
        && git_grep_search_args(&parts[1..]).is_some()
}

fn sequence_starts_with_local_reader(parts: &[String]) -> bool {
    let command_parts = unwrapped_command_parts(parts);
    if command_parts.is_empty() {
        return false;
    }
    parts_are_git_grep(&command_parts)
        || LOCAL_READ_COMMANDS.contains(&executable_name_lower(&command_parts[0]).as_str())
}

/// `_codex_command_parts_may_read_local_content`.
fn parts_may_read_local_content(parts: &[String], scope: Scope) -> bool {
    for start in command_start_indexes(parts) {
        let previous = if start > 0 {
            Some(parts[start - 1].as_str())
        } else {
            None
        };
        let segment_parts = command_segment_parts(parts, start);
        if previous == Some("|") {
            if sequence_is_read_only_source_inspection(&segment_parts, scope) {
                return true;
            }
            continue;
        }
        if sequence_starts_with_local_reader(&segment_parts) {
            return true;
        }
    }
    false
}

/// `_codex_pipeline_segment_may_read_local_content`.
fn pipeline_segment_may_read_local_content(segment: &str, index: usize, scope: Scope) -> bool {
    let Some(parts) = shell_split(segment) else {
        return true;
    };
    if parts.is_empty() {
        return false;
    }
    if index == 0 {
        return parts_are_environment_dump(&parts) || parts_may_read_local_content(&parts, scope);
    }
    search_or_view(segment, scope)
}

/// `_codex_command_reads_environment_pipeline`.
pub(crate) fn reads_environment_pipeline(command_text: &str) -> bool {
    let Some(parts) = shell_split(command_text) else {
        return false;
    };
    let starts = command_start_indexes(&parts);
    let Some(first) = starts.first() else {
        return false;
    };
    if !parts_are_environment_dump(&command_segment_parts(&parts, *first)) {
        return false;
    }
    let mut saw_pipeline = false;
    for start in &starts[1..] {
        if parts[start - 1] != "|" {
            return false;
        }
        saw_pipeline = true;
    }
    saw_pipeline
}

/// The context-free tail of `_codex_command_may_read_local_content`.
pub(crate) fn may_read_local_content_tail(command_text: &str, scope: Scope) -> bool {
    if reads_environment_pipeline(command_text) {
        return true;
    }
    if ["$(", "${", "`"]
        .iter()
        .any(|marker| command_text.contains(marker))
    {
        return true;
    }
    if let Some(segments) = split_pipeline(command_text) {
        return segments.iter().enumerate().any(|(index, segment)| {
            pipeline_segment_may_read_local_content(segment, index, scope)
        });
    }
    match shell_split(command_text) {
        None => true,
        Some(parts) => parts_may_read_local_content(&parts, scope),
    }
}

fn pytest_target_arg(value: &str) -> bool {
    let stripped = crate::codex_output_py::py_strip(value);
    !stripped.is_empty()
        && (stripped.contains("::")
            || stripped.ends_with(".py")
            || stripped == "tests"
            || stripped.starts_with("tests/")
            || stripped.contains("/tests/")
            || stripped.starts_with("test_"))
}

fn segment_is_safe_directory_change(parts: &[String]) -> bool {
    let command_parts = unwrapped_command_parts(parts);
    command_parts.len() == 2 && executable_name_lower(&command_parts[0]) == "cd"
}

fn segment_is_exit_code_echo(parts: &[String]) -> bool {
    let command_parts = unwrapped_command_parts(parts);
    command_parts.len() == 2
        && executable_name_lower(&command_parts[0]) == "echo"
        && command_parts[1].starts_with("__EXIT_CODE__:$?")
}

fn segment_is_focused_pytest(parts: &[String]) -> bool {
    let filtered: Vec<String> = parts
        .iter()
        .filter(|part| !SAFE_SHELL_REDIRECTION_TOKENS.contains(&part.as_str()))
        .cloned()
        .collect();
    let command_parts = unwrapped_command_parts(&filtered);
    let Some(first) = command_parts.first() else {
        return false;
    };
    let executable = executable_name_lower(first);
    let args: &[String] = if executable == "pytest" {
        &command_parts[1..]
    } else if executable.starts_with("python")
        && command_parts.len() >= 3
        && command_parts[1] == "-m"
        && command_parts[2] == "pytest"
    {
        &command_parts[3..]
    } else {
        return false;
    };
    let mut saw_target = false;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if PYTEST_SAFE_FLAGS.contains(&arg)
            || PYTEST_SAFE_FLAG_PREFIXES.iter().any(|p| arg.starts_with(p))
        {
            index += 1;
            continue;
        }
        if PYTEST_SAFE_FLAGS_WITH_VALUES.contains(&arg) {
            if index + 1 >= args.len() {
                return false;
            }
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            return false;
        }
        if pytest_target_arg(arg) {
            saw_target = true;
            index += 1;
            continue;
        }
        return false;
    }
    saw_target
}

/// `_codex_command_is_focused_pytest_verification`.
pub(crate) fn is_focused_pytest_verification(command_text: &str) -> bool {
    let Some(parts) = shell_split(command_text) else {
        return false;
    };
    if parts.is_empty() {
        return false;
    }
    let mut saw_pytest = false;
    for start in command_start_indexes(&parts) {
        let segment_parts = command_segment_parts(&parts, start);
        if segment_parts.is_empty() {
            return false;
        }
        let separator = if start > 0 {
            Some(parts[start - 1].as_str())
        } else {
            None
        };
        if matches!(separator, Some("|" | "|&" | "||" | "&")) {
            return false;
        }
        if segment_is_safe_directory_change(&segment_parts)
            || segment_is_exit_code_echo(&segment_parts)
        {
            continue;
        }
        if segment_is_focused_pytest(&segment_parts) {
            saw_pytest = true;
            continue;
        }
        return false;
    }
    saw_pytest
}

/// `_codex_command_is_read_only_git_metadata`.
pub(crate) fn is_read_only_git_metadata(command_text: &str, scope: Scope) -> bool {
    if ["\n", "\r", ";", "&", "|", "<", ">", "`", "$("]
        .iter()
        .any(|marker| command_text.contains(marker))
    {
        return false;
    }
    let Some(parts) = shlex_split(command_text) else {
        return false;
    };
    if parts.first().is_none_or(|first| first != "git") {
        return false;
    }
    let ctx = scope.ctx;
    let base = scope
        .cwd
        .map(|cwd| {
            if cwd.is_absolute() {
                cwd.clone()
            } else {
                ctx.process_cwd.join(&cwd.to_string())
            }
        })
        .unwrap_or_else(|| ctx.process_cwd.clone());
    let Some(mut execution_cwd) = pyfs::resolve(&base) else {
        return false;
    };
    let host = ctx.host;
    if !host.git_safety(
        GitCheck::ResolveBinary,
        Some(&execution_cwd.to_string()),
        &[],
    ) || !host.git_safety(GitCheck::ConfigEnvironmentClean, None, &[])
    {
        return false;
    }
    let mut args: Vec<String> = parts[1..].to_vec();
    if args.first().is_some_and(|first| first == "-C") {
        if args.len() < 3 {
            return false;
        }
        let Some(expanded) = ctx.expanduser(&args[1]) else {
            return false;
        };
        let joined = if expanded.is_absolute() {
            expanded
        } else {
            execution_cwd.join(&expanded.to_string())
        };
        let Some(target) = pyfs::resolve(&joined) else {
            return false;
        };
        if !matches!(pyfs::exists(&target), Ok(true))
            || target.relative_to(&execution_cwd).is_none()
        {
            return false;
        }
        if !matches!(pyfs::is_dir(&target), Ok(true)) {
            return false;
        }
        execution_cwd = target;
        args = args[2..].to_vec();
    }
    let Some(first) = args.first() else {
        return false;
    };
    if first.starts_with('-') {
        return false;
    }
    if first == "status" {
        return host.git_safety(GitCheck::StatusArguments, None, &args)
            && host.git_safety(
                GitCheck::StatusConfig,
                Some(&execution_cwd.to_string()),
                &[],
            );
    }
    if args.len() >= 2 && args[0] == "worktree" && args[1] == "list" {
        return args[2..].iter().all(|arg| {
            matches!(arg.as_str(), "--porcelain" | "-v" | "--verbose" | "-z")
                || arg.starts_with("--expire=")
        });
    }
    args.len() >= 2
        && args[0] == "branch"
        && args[1] == "--list"
        && args[2..].iter().all(|arg| !arg.starts_with('-'))
}
