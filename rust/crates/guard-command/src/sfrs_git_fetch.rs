//! Origin-shaped Git fetch recognition (`git_origin_refresh.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::sfrs_shell_tokens::shell_segment_primary_command;

const ORIGIN_REFRESH_FLAGS: [&str; 5] = ["-q", "--quiet", "--no-tags", "--prune", "-p"];
const GIT_GLOBAL_FLAG_OPTIONS: [&str; 10] = [
    "--bare",
    "--literal-pathspecs",
    "--no-advice",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-pager",
    "--no-replace-objects",
    "--paginate",
    "-P",
    "-p",
];
const GIT_GLOBAL_VALUE_OPTIONS: [&str; 5] = [
    "-C",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
];
const GIT_EXECUTION_VALUE_OPTIONS: [&str; 3] = ["-c", "--config-env", "--exec-path"];

/// `re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", text)`.
fn is_origin_ref(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 256 || !text.is_ascii() {
        return false;
    }
    bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

/// `origin_shaped_git_fetch_args`: a named-origin refresh, not a URL or `--all`.
pub(crate) fn origin_shaped_git_fetch_args(args: &[String]) -> bool {
    if args.is_empty() || args.len() > 16 {
        return false;
    }
    let mut remote: Option<&str> = None;
    let mut refs = 0usize;
    for arg in args {
        if ORIGIN_REFRESH_FLAGS.contains(&arg.as_str()) {
            continue;
        }
        if arg.starts_with('-') || (remote.is_none() && arg != "origin") {
            return false;
        }
        if remote.is_none() {
            remote = Some(arg);
            continue;
        }
        if !is_origin_ref(arg) {
            return false;
        }
        refs += 1;
    }
    remote == Some("origin") && refs <= 12
}

/// `git_fetch_operands`: the arguments after a `git fetch` subcommand.
pub(crate) fn git_fetch_operands(tokens: &[String]) -> Option<Vec<String>> {
    let (command_name, command_index) = shell_segment_primary_command(tokens);
    if command_name.as_deref() != Some("git") {
        return None;
    }
    let args = &tokens[command_index? + 1..];
    let mut index = 0usize;
    while index < args.len() {
        let token = args[index].as_str();
        let (option_name, value) = match token.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (token, None),
        };
        if GIT_GLOBAL_FLAG_OPTIONS.contains(&token) {
            index += 1;
            continue;
        }
        if GIT_EXECUTION_VALUE_OPTIONS.contains(&option_name) {
            return None;
        }
        if GIT_GLOBAL_VALUE_OPTIONS.contains(&option_name) {
            if let Some(value) = value {
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
        if token != "fetch" {
            return None;
        }
        return Some(args[index + 1..].to_vec());
    }
    None
}

/// `command_is_origin_shaped_git_fetch`: every executable segment is a refresh.
pub(crate) fn command_is_origin_shaped_git_fetch(segments: &[Vec<String>]) -> bool {
    if segments.is_empty() {
        return false;
    }
    segments.iter().all(|tokens| {
        git_fetch_operands(tokens).is_some_and(|operands| origin_shaped_git_fetch_args(&operands))
    })
}
