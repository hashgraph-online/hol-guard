//! Cached-diff command shape recognition for staged-index inspection
//! (`runtime/git_index_inspection.py`: token and operand parsing).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_env::Ctx;
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use std::path::{Path, PathBuf};

const CONTROL_PREFIXES: [&str; 6] = ["!", "elif", "else", "fi", "if", "then"];
const GIT_GLOBAL_FLAG_OPTIONS: [&str; 6] = [
    "--literal-pathspecs",
    "--no-advice",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-pager",
    "--no-replace-objects",
];
const GIT_GLOBAL_VALUE_OPTIONS: [&str; 8] = [
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
    "-C",
    "-c",
];
const EXECUTION_ROUTING_OPTIONS: [&str; 3] = ["-c", "--config-env", "--exec-path"];
const REPOSITORY_SELECTOR_OPTIONS: [&str; 8] = [
    "--bare",
    "--git-dir",
    "--namespace",
    "--paginate",
    "--super-prefix",
    "--work-tree",
    "-P",
    "-p",
];
const INDEX_DIFF_FLAGS: [&str; 2] = ["--cached", "--staged"];
const SAFE_CACHED_DIFF_FLAGS: [&str; 7] = [
    "--cached",
    "--check",
    "--name-only",
    "--name-status",
    "--staged",
    "--stat",
    "HEAD",
];

/// `_CACHED_DIFF_KIND`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CachedDiffKind {
    Owned,
    Routed,
}

pub(crate) fn listed(list: &[&str], token: &str) -> bool {
    list.contains(&token)
}

pub(crate) fn option_name(token: &str) -> &str {
    token.split('=').next().unwrap_or(token)
}

/// `executable_tokens`: `None` rejects; an empty list is a no-op such as `fi`.
pub(crate) fn executable_tokens(tokens: &[String]) -> Option<Vec<String>> {
    let mut index = 0;
    while index < tokens.len() && listed(&CONTROL_PREFIXES, &tokens[index]) {
        if tokens[index] == "fi" && tokens.len() != 1 {
            return None;
        }
        index += 1;
    }
    Some(tokens[index..].to_vec())
}

/// The `git` command's arguments inside a stripped segment.
fn stripped_git_args(tokens: &[String]) -> Option<Vec<String>> {
    let stripped = executable_tokens(tokens)?;
    if stripped.is_empty() {
        return None;
    }
    let (name, index) = shell_segment_primary_command(&stripped);
    if name.as_deref() != Some("git") {
        return None;
    }
    Some(stripped[index? + 1..].to_vec())
}

/// `cached_diff_kind`.
pub(crate) fn cached_diff_kind(tokens: &[String]) -> Option<CachedDiffKind> {
    let args = stripped_git_args(tokens)?;
    let mut index = 0;
    let mut routed = false;
    while index < args.len() {
        let token = args[index].as_str();
        let name = option_name(token);
        if listed(&GIT_GLOBAL_FLAG_OPTIONS, token) {
            index += 1;
            continue;
        }
        if token == "-c" || (token.starts_with("-c") && !token.starts_with("-C")) {
            routed = true;
            if token == "-c" {
                if index + 1 >= args.len() {
                    return None;
                }
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if listed(&GIT_GLOBAL_VALUE_OPTIONS, name) {
            if listed(&EXECUTION_ROUTING_OPTIONS, name) {
                routed = true;
            }
            if let Some((_, value)) = token.split_once('=') {
                if value.is_empty() {
                    return None;
                }
                index += 1;
                continue;
            }
            if index + 1 >= args.len() {
                return None;
            }
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        if token != "diff" {
            return None;
        }
        let operands = &args[index + 1..];
        let end = operands
            .iter()
            .position(|operand| operand == "--")
            .unwrap_or(operands.len());
        if !operands[..end]
            .iter()
            .any(|operand| listed(&INDEX_DIFF_FLAGS, operand))
        {
            return None;
        }
        return Some(if routed {
            CachedDiffKind::Routed
        } else {
            CachedDiffKind::Owned
        });
    }
    None
}

pub(crate) fn tokens_are_cached_diff(tokens: &[String]) -> bool {
    cached_diff_kind(tokens) == Some(CachedDiffKind::Owned)
}

/// `command_has_execution_routed_git_cached_diff`.
pub(crate) fn command_has_execution_routed_git_cached_diff(segments: &[Vec<String>]) -> bool {
    segments
        .iter()
        .any(|tokens| cached_diff_kind(tokens) == Some(CachedDiffKind::Routed))
}

/// `command_has_owned_git_cached_diff`.
pub(crate) fn command_has_owned_git_cached_diff(segments: &[Vec<String>]) -> bool {
    !command_has_execution_routed_git_cached_diff(segments)
        && segments
            .iter()
            .any(|tokens| cached_diff_kind(tokens) == Some(CachedDiffKind::Owned))
}

/// `git_diff_operands`.
pub(crate) fn git_diff_operands(tokens: &[String]) -> Option<Vec<String>> {
    if cached_diff_kind(tokens) != Some(CachedDiffKind::Owned) {
        return None;
    }
    let args = stripped_git_args(tokens)?;
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if listed(&GIT_GLOBAL_FLAG_OPTIONS, token) {
            index += 1;
            continue;
        }
        if listed(&GIT_GLOBAL_VALUE_OPTIONS, option_name(token)) {
            index += if token.contains('=') { 1 } else { 2 };
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        if token != "diff" {
            return None;
        }
        return Some(args[index + 1..].to_vec());
    }
    None
}

/// Without a `--`, git reads an operand that names a revision as a revision and
/// only falls back to a pathspec when the name is present in the working tree.
/// The separator form admits no revision but `HEAD`, so the bare form holds to
/// the same policy the only way git itself tells the two apart: the operand has
/// to name something that is already there. `git diff --cached origin/main`
/// stays a review; a name that is both a file and a ref makes git refuse the
/// command as ambiguous rather than diff the ref.
fn operand_is_a_present_path(operand: &str, cwd: Option<&Path>) -> bool {
    if operand.starts_with(':') {
        // `:!dir` and `:^dir` exclusions. A ref name cannot carry a colon, so
        // git can only read these as pathspecs.
        return true;
    }
    let Some(cwd) = cwd else {
        return false;
    };
    // `symlink_metadata` rather than `exists`: a broken symlink is still an
    // entry git sees, and any other error (an unreadable parent) refuses.
    cwd.join(operand).symlink_metadata().is_ok()
}

/// The directory git resolves a bare operand against. A leading `-C <dir>`
/// route moves it there, so an operand that is present beside the shell's own
/// working directory proves nothing about the repository git actually reads;
/// a relative route needs that working directory to resolve at all.
pub(crate) fn cached_diff_operand_directory(
    tokens: &[String],
    cwd: Option<&Path>,
) -> Option<PathBuf> {
    let route = stripped_git_args(tokens)
        .filter(|args| args.first().map(String::as_str) == Some("-C"))
        .and_then(|args| args.get(1).cloned());
    let Some(route) = route else {
        return cwd.map(Path::to_path_buf);
    };
    let route = PathBuf::from(route);
    if route.is_absolute() {
        return Some(route);
    }
    cwd.map(|cwd| cwd.join(route))
}

/// `_cached_diff_operands_are_safe`.
pub(crate) fn cached_diff_operands_are_safe(
    args: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if args.len() > 20 {
        return false;
    }
    let has_index_flag =
        |items: &[String]| items.iter().any(|item| listed(&INDEX_DIFF_FLAGS, item));
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        if !has_index_flag(args) {
            return false;
        }
        // `git diff --cached src/app.ts` is the same staged read as the `--`
        // form; git takes the trailing operands as pathspecs. Hold every
        // option to the safe list so an output-writing flag such as
        // `--output=<file>` can never reach the pathspec check.
        let paths: Vec<String> = args
            .iter()
            .filter(|arg| !listed(&SAFE_CACHED_DIFF_FLAGS, arg))
            .cloned()
            .collect();
        if paths.is_empty() {
            return true;
        }
        if paths.len() > 16 || paths.iter().any(|path| path.starts_with('-')) {
            return false;
        }
        if !paths
            .iter()
            .all(|path| operand_is_a_present_path(path, cwd))
        {
            return false;
        }
        return ctx.host.cached_diff_pathspecs(&paths);
    };
    let revisions = &args[..separator];
    if !has_index_flag(revisions) {
        return false;
    }
    let paths = &args[separator + 1..];
    if paths.is_empty() || paths.len() > 16 {
        return false;
    }
    if revisions
        .iter()
        .any(|arg| !listed(&SAFE_CACHED_DIFF_FLAGS, arg))
    {
        return false;
    }
    ctx.host.cached_diff_pathspecs(paths)
}

/// `_proof_cached_diff_tokens`.
pub(crate) fn proof_cached_diff_tokens(tokens: &[String]) -> Vec<String> {
    let (name, index) = shell_segment_primary_command(tokens);
    let (Some("git"), Some(index)) = (name.as_deref(), index) else {
        return ["git", "diff", "--cached", "--check"]
            .map(str::to_owned)
            .to_vec();
    };
    let mut proof = tokens[..=index].to_vec();
    let args = &tokens[index + 1..];
    if args.first().map(String::as_str) == Some("-C") && args.len() >= 2 {
        proof.extend(["-C".to_owned(), args[1].clone()]);
    }
    proof.extend(["diff", "--cached", "--check"].map(str::to_owned));
    proof
}

/// `_args_have_repository_selector`.
fn args_have_repository_selector(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        let name = option_name(token);
        if token == "-C" || token.starts_with("-C") || listed(&REPOSITORY_SELECTOR_OPTIONS, name) {
            return true;
        }
        if listed(&GIT_GLOBAL_FLAG_OPTIONS, token) {
            index += 1;
            continue;
        }
        if listed(&GIT_GLOBAL_VALUE_OPTIONS, name) {
            index += if token.contains('=') { 1 } else { 2 };
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return false;
    }
    false
}

/// `_has_unproven_repository_selector`.
pub(crate) fn has_unproven_repository_selector(tokens: &[String]) -> bool {
    let Some(args) = stripped_git_args(tokens) else {
        return true;
    };
    if args.first().map(String::as_str) == Some("-C") {
        if args.len() < 2 || args[1].is_empty() || args[1].starts_with('-') {
            return true;
        }
        return args_have_repository_selector(&args[2..]);
    }
    args_have_repository_selector(&args)
}
