//! Structural recognition of bounded read-only Git ancestry audits
//! (`read_only_git_audit.py`). Git trust and the execution-free log
//! configuration check stay with the resident through `InspectionHost`.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_static_safety::which_for_execution_cwd;
use crate::shell_execution_context::{
    model_shell_execution_context, ShellExecutionContext, ShellExecutionSegment,
};

const SAFE_LOOP_VARIABLES: [&str; 5] = ["candidate", "commit", "ref", "rev", "sha"];
const MAX_COMMITS: usize = 32;
const MAX_PID_BYTES: usize = 32;

fn controls(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len() && actual.iter().zip(expected).all(|(a, b)| a == b)
}

fn tokens_are(segment: &ShellExecutionSegment, expected: &[&str]) -> bool {
    controls(&segment.tokens, expected)
}

/// `re.fullmatch(r"[0-9A-Fa-f]{7,40}", text)`.
fn is_commit_id(text: &str) -> bool {
    (7..=40).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `trusted_git_binary_for_cwd`: the resolved Git when the resident trusts it.
pub(crate) fn trusted_git_binary_for_cwd(cwd: &Path, ctx: &Ctx) -> Option<String> {
    let located = which_for_execution_cwd("git", cwd, ctx)?;
    let resolved = fs::canonicalize(located)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let cwd_text = fs::canonicalize(cwd).map_or_else(
        |_| cwd.to_string_lossy().into_owned(),
        |p| p.to_string_lossy().into_owned(),
    );
    ctx.host
        .git_binary_trusted(&resolved, &cwd_text)
        .then_some(resolved)
}

/// `is_read_only_git_ancestry_audit`: one literal commit loop with optional
/// bounded local status reads.
pub(crate) fn is_read_only_git_ancestry_audit(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    ctx: &Ctx,
) -> bool {
    let initial_root = cwd.unwrap_or(home_dir);
    let context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
    );
    if !context.complete || context.segments.len() < 6 {
        return false;
    }
    let Some(workspace_root) = leading_workspace_root(&context) else {
        return false;
    };
    if !is_within(&workspace_root, home_dir) && !is_within(&workspace_root, initial_root) {
        return false;
    }
    let segments = &context.segments;
    let mut index = 1usize;
    if is_static_echo(&segments[index], "&&", "&&") {
        index += 1;
    }
    let Some(loop_end) = literal_ancestry_loop_end(segments, index, &workspace_root, ctx) else {
        return false;
    };
    let suffix = &segments[loop_end..];
    suffix.is_empty() || safe_status_suffix(suffix, &workspace_root, ctx)
}

/// `_leading_workspace_root`.
pub(crate) fn leading_workspace_root(context: &ShellExecutionContext) -> Option<PathBuf> {
    let segment = context.segments.first()?;
    if segment.tokens.first().map(String::as_str) != Some("cd")
        || segment.tokens.len() != 2
        || !segment.control_before.is_empty()
        || !controls(&segment.control_after, &["&&"])
        || segment.directory_operation.as_deref() != Some("cd")
        || context.segments.len() < 2
    {
        return None;
    }
    let root = context.segments[1].effective_cwd.as_ref()?;
    fs::canonicalize(root).ok()
}

/// `_literal_ancestry_loop_end`.
pub(crate) fn literal_ancestry_loop_end(
    segments: &[ShellExecutionSegment],
    index: usize,
    workspace_root: &Path,
    ctx: &Ctx,
) -> Option<usize> {
    if index + 4 >= segments.len() {
        return None;
    }
    let [start, query, yes, no, end] = &segments[index..index + 5] else {
        return None;
    };
    if start.tokens.len() < 4 || start.tokens[0] != "for" || start.tokens[2] != "in" {
        return None;
    }
    let variable = start.tokens[1].as_str();
    let commits = &start.tokens[3..];
    if !SAFE_LOOP_VARIABLES.contains(&variable)
        || !(1..=MAX_COMMITS).contains(&commits.len())
        || !commits.iter().all(|commit| is_commit_id(commit))
        || !controls(&start.control_after, &[";"])
        || !(controls(&start.control_before, &["&&"]) || controls(&start.control_before, &[";"]))
    {
        return None;
    }
    let dollar = format!("${variable}");
    let expected_query = [
        "do",
        "git",
        "merge-base",
        "--is-ancestor",
        dollar.as_str(),
        "HEAD",
        "2>/dev/null",
    ];
    if !tokens_are(query, &expected_query)
        || !controls(&query.control_before, &[";"])
        || !controls(&query.control_after, &["&&"])
    {
        return None;
    }
    if !query
        .effective_cwd
        .as_deref()
        .is_some_and(|cwd| same_path(cwd, workspace_root))
    {
        return None;
    }
    trusted_git_binary_for_cwd(workspace_root, ctx)?;
    let yes_text = format!("{dollar} YES");
    if !tokens_are(yes, &["echo", &yes_text])
        || !controls(&yes.control_before, &["&&"])
        || !controls(&yes.control_after, &["||"])
    {
        return None;
    }
    let no_text = format!("{dollar} NO");
    if !tokens_are(no, &["echo", &no_text])
        || !controls(&no.control_before, &["||"])
        || !controls(&no.control_after, &[";"])
    {
        return None;
    }
    if !tokens_are(end, &["done"])
        || !controls(&end.control_before, &[";"])
        || !(end.control_after.is_empty() || controls(&end.control_after, &[";"]))
    {
        return None;
    }
    Some(index + 5)
}

/// `_safe_status_suffix`.
pub(crate) fn safe_status_suffix(
    segments: &[ShellExecutionSegment],
    workspace_root: &Path,
    ctx: &Ctx,
) -> bool {
    let mut index = 0usize;
    if index < segments.len() && is_static_echo(&segments[index], ";", ";") {
        index += 1;
    }
    if index < segments.len() && is_git_log(&segments[index], workspace_root, ctx) {
        index += 1;
        if index < segments.len() && is_static_echo(&segments[index], ";", ";") {
            index += 1;
        }
        if index + 2 != segments.len() {
            return false;
        }
        let fallback = &segments[index + 1];
        return is_numeric_file_cat(&segments[index], workspace_root)
            && fallback.tokens.len() == 2
            && fallback.tokens[0] == "echo"
            && !fallback.tokens[1].contains('$')
            && !fallback.tokens[1].contains('`')
            && controls(&fallback.control_before, &["||"])
            && fallback.control_after.is_empty();
    }
    if index + 5 != segments.len() {
        return false;
    }
    let [head, condition, success, fallback, end] = &segments[index..index + 5] else {
        return false;
    };
    if !tokens_are(head, &["echo", "HEAD: $(git log -1 --oneline)"])
        || !controls(&head.control_before, &[";"])
    {
        return false;
    }
    if !git_log_is_execution_free(workspace_root, ctx) {
        return false;
    }
    if condition.tokens.len() != 5
        || condition.tokens[..3] != ["if", "[", "-f"]
        || condition.tokens[4] != "]"
    {
        return false;
    }
    let target = condition.tokens[3].as_str();
    if !controls(&condition.control_before, &[";"]) || !controls(&condition.control_after, &[";"]) {
        return false;
    }
    let lock = format!("LOCK: $(cat {target})");
    if !tokens_are(success, &["then", "echo", &lock]) || !controls(&success.control_before, &[";"])
    {
        return false;
    }
    if fallback.tokens.len() != 3
        || fallback.tokens[..2] != ["else", "echo"]
        || !controls(&fallback.control_before, &[";"])
    {
        return false;
    }
    if fallback.tokens[2].contains('$') || fallback.tokens[2].contains('`') {
        return false;
    }
    if !tokens_are(end, &["fi"])
        || !controls(&end.control_before, &[";"])
        || !end.control_after.is_empty()
    {
        return false;
    }
    numeric_file_is_safe(target, workspace_root)
}

/// `_is_git_log`.
pub(crate) fn is_git_log(
    segment: &ShellExecutionSegment,
    workspace_root: &Path,
    ctx: &Ctx,
) -> bool {
    tokens_are(segment, &["git", "log", "-1", "--oneline"])
        && controls(&segment.control_before, &[";"])
        && controls(&segment.control_after, &[";"])
        && git_log_is_execution_free(workspace_root, ctx)
}

/// `_git_log_is_execution_free`.
pub(crate) fn git_log_is_execution_free(workspace_root: &Path, ctx: &Ctx) -> bool {
    trusted_git_binary_for_cwd(workspace_root, ctx).is_some_and(|git| {
        ctx.host
            .git_log_execution_free_config(&workspace_root.to_string_lossy(), &git)
    })
}

/// `_is_numeric_file_cat`.
pub(crate) fn is_numeric_file_cat(segment: &ShellExecutionSegment, workspace_root: &Path) -> bool {
    segment.tokens.len() == 3
        && segment.tokens[0] == "cat"
        && segment.tokens[2] == "2>/dev/null"
        && controls(&segment.control_before, &[";"])
        && controls(&segment.control_after, &["||"])
        && numeric_file_is_safe(&segment.tokens[1], workspace_root)
}

/// `re.fullmatch(r"\.[A-Za-z0-9_.-]{1,128}\.lock\.d", text)`.
fn is_lock_directory(text: &str) -> bool {
    let Some(inner) = text
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".lock.d"))
    else {
        return false;
    };
    (1..=128).contains(&inner.len())
        && inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `re.fullmatch(rb"[0-9]+(?:\r?\n)?", payload)`.
fn is_pid_payload(payload: &[u8]) -> bool {
    let body = payload
        .strip_suffix(b"\n")
        .map(|rest| rest.strip_suffix(b"\r").unwrap_or(rest))
        .unwrap_or(payload);
    !body.is_empty() && body.iter().all(u8::is_ascii_digit)
}

/// `_numeric_file_is_safe`.
pub(crate) fn numeric_file_is_safe(target_text: &str, workspace_root: &Path) -> bool {
    if target_text.is_empty()
        || target_text.starts_with(['-', '~', '/'])
        || target_text.contains('$')
        || target_text.contains('`')
    {
        return false;
    }
    let parts = PyPath::new(target_text).parts();
    if parts.len() != 2 || parts[1] != "pid" || !is_lock_directory(&parts[0]) {
        return false;
    }
    let root = PyPath::new(&workspace_root.to_string_lossy());
    let target = root.join(&format!("{}/{}", parts[0], parts[1]));
    let Some(resolved) = pyfs::resolve(&target) else {
        return false;
    };
    if resolved.relative_to(&root).is_none() {
        return false;
    }
    match pyfs::exists(&target) {
        Ok(false) => return true,
        Ok(true) => {}
        Err(()) => return false,
    }
    if pyfs::is_symlink(&target) != Ok(false) || pyfs::is_file(&target) != Ok(true) {
        return false;
    }
    let Ok(handle) = fs::File::open(target.to_string()) else {
        return false;
    };
    let mut payload = Vec::new();
    if handle
        .take(MAX_PID_BYTES as u64 + 1)
        .read_to_end(&mut payload)
        .is_err()
    {
        return false;
    }
    payload.len() <= MAX_PID_BYTES && is_pid_payload(&payload)
}

/// `_is_static_echo`.
pub(crate) fn is_static_echo(segment: &ShellExecutionSegment, before: &str, after: &str) -> bool {
    segment.tokens.len() == 2
        && segment.tokens[0] == "echo"
        && !segment.tokens[1].contains('$')
        && !segment.tokens[1].contains('`')
        && controls(&segment.control_before, &[before])
        && controls(&segment.control_after, &[after])
}

/// `_same_path`: `left.resolve(strict=True) == right`.
pub(crate) fn same_path(left: &Path, right: &Path) -> bool {
    fs::canonicalize(left).is_ok_and(|resolved| resolved == right)
}

/// `_is_within`: `path.relative_to(parent.resolve(strict=True))`.
pub(crate) fn is_within(path: &Path, parent: &Path) -> bool {
    fs::canonicalize(parent).is_ok_and(|parent| {
        PyPath::new(&path.to_string_lossy())
            .relative_to(&PyPath::new(&parent.to_string_lossy()))
            .is_some()
    })
}
