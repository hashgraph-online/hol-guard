//! Proof for routine Oh My Pi hashline edits.
//!
//! Oh My Pi's `edit` tool takes one `input` string: an optional
//! `*** Begin Patch` line, then one `[PATH#TAG]` header per file followed by
//! `PUT`/`CUT` operations and `+` body rows, then `*** End Patch`. Models
//! often add unified-diff `-old` rows under a `PUT`; Oh My Pi drops them or
//! keeps them as body text, and never reads them as a header or operation.
//! The body rows are file content, not commands, so the edit gets the same
//! bounded proof as a Codex `apply_patch`: every header must name a file that
//! the native file write proof accepts and that is not agent instruction or
//! VCS metadata.
//!
//! Oh My Pi's own parser forgives a lot: it unquotes paths, strips
//! `Update File:`-style noise and leading `***`, and recovers lowercase tags.
//! This parser accepts only the plain grammar, so every target it reports is
//! the file Oh My Pi would open. Deletes (`REM`), moves (`MV`), quoted or
//! decorated paths, `~` other than a leading `~/`, and anything else it does
//! not recognize leave the edit unproven.

use std::path::Path;

const MAX_PATCH_TARGETS: usize = 64;
const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const TAG_LENGTH: usize = 4;

/// What the proof concluded about a hashline edit.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum HashlineEdit {
    /// Every target is an ordinary workspace or worktree file.
    Routine,
    /// Every target is ordinary or names a path that does not exist, and at
    /// least one does not exist. The edit cannot apply, so the agent should
    /// fix the path rather than wait on an approval. Holds the first missing
    /// path as the header wrote it.
    MissingTarget(String),
}

/// Files a hashline `input` edits, each with whether a header carried a
/// snapshot tag, or `None` when the input is not a plain, well-formed
/// hashline patch limited to `PUT` and `CUT` operations.
pub(super) fn hashline_targets(input: &str) -> Option<Vec<(String, bool)>> {
    // The generic extractor already rejects longer strings; keep the same cap.
    if input.len() > crate::MAX_COMMAND_BYTES || input.contains('\0') {
        return None;
    }
    let mut lines = input.trim().lines().peekable();
    if lines.peek().is_some_and(|line| line.trim() == BEGIN_PATCH) {
        lines.next();
    }
    let mut targets: Vec<(String, bool)> = Vec::new();
    let mut in_file = false;
    let mut in_put = false;
    let mut ended = false;
    for line in lines {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if ended {
            if line.trim().is_empty() {
                continue;
            }
            return None;
        }
        if line.trim().is_empty() {
            continue;
        }
        if line.trim() == END_PATCH {
            ended = true;
            continue;
        }
        if line.starts_with('[') {
            let (path, tagged) = header_path(line.trim_end())?;
            if let Some(target) = targets.iter_mut().find(|(known, _)| known == path) {
                target.1 |= tagged;
            } else if targets.len() == MAX_PATCH_TARGETS {
                return None;
            } else {
                targets.push((path.to_owned(), tagged));
            }
            in_file = true;
            in_put = false;
            continue;
        }
        let operation = line.starts_with("PUT ") || line.starts_with("CUT ");
        if operation {
            in_put = line.starts_with("PUT ");
        }
        let body = line.starts_with('+') || (in_put && line.starts_with('-'));
        if !in_file || !(operation || body) {
            return None;
        }
    }
    (!targets.is_empty()).then_some(targets)
}

/// Every header path in order, repeats included, the way Oh My Pi lists them
/// in the `path`/`paths` fields it adds to an edit's hook input. `None` when a
/// header is not plain or a legacy `¶` header is present.
pub(super) fn header_paths(input: &str) -> Option<Vec<&str>> {
    let mut paths = Vec::new();
    for line in input.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim_start().starts_with('¶') {
            return None;
        }
        if line.starts_with('[') && line.ends_with(']') {
            paths.push(header_path(line)?.0);
        }
    }
    Some(paths)
}

fn header_path(line: &str) -> Option<(&str, bool)> {
    let body = line.strip_prefix('[')?.strip_suffix(']')?;
    let (path, tagged) = match body.rsplit_once('#') {
        Some((path, tag))
            if tag.len() == TAG_LENGTH && tag.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            (path, true)
        }
        Some(_) => return None,
        None => (body, false),
    };
    // Oh My Pi trims the path with JavaScript's `trim`. Without control
    // characters or a byte order mark, that trims exactly what `str::trim`
    // does, so a padded path names the same file once trimmed.
    if path.chars().any(|c| c.is_control() || c == '\u{feff}') {
        return None;
    }
    let path = path.trim();
    // Oh My Pi rewrites quoted, starred and `Update File:`-prefixed paths
    // before opening them, and a scheme names another location, so only a
    // path it would open as written is reported. It opens a leading `~/`
    // under the home folder, and shows paths that way, so models copy it.
    let home_relative = path
        .strip_prefix('~')
        .is_none_or(|rest| rest.starts_with('/'));
    // A Windows drive path (`C:\Users\...` or `C:/Users/...`) is a host
    // path: Oh My Pi only routes registered `scheme:/` names elsewhere, and
    // no scheme is one letter. A drive-relative `C:name` stays unproven, and
    // so does a backslash spelling off Windows, where it is one relative name.
    let rest = match path.as_bytes() {
        [drive, b':', b'/', ..] if drive.is_ascii_alphabetic() => &path[2..],
        [drive, b':', b'\\', ..] if cfg!(windows) && drive.is_ascii_alphabetic() => &path[2..],
        _ => path,
    };
    let plain = !path.is_empty()
        && home_relative
        && !path.starts_with(['"', '\'', '*'])
        && !rest.contains(['#', ':']);
    plain.then_some((path, tagged))
}

/// Judges an Oh My Pi hashline `edit` input against the session folder.
pub(super) fn evaluate_hashline_edit(
    input: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<HashlineEdit> {
    let workspace = cwd.and_then(|root| std::fs::canonicalize(root).ok())?;
    let targets = hashline_targets(input)?;
    let mut missing: Option<&str> = None;
    for (written, tagged) in &targets {
        let target = &match written.strip_prefix("~/") {
            Some(rest) => Path::new(home_dir?).join(rest).to_str()?.to_owned(),
            None => written.clone(),
        };
        // Only an ordinary name may say it is missing; a sensitive or
        // protected one keeps its review.
        let missing_target = || {
            super::safe_reads::missing_read_target(target, home_dir, cwd, false)
                && !super::sensitive_command(target)
                && !super::apply_patch_writes::protected_name(Path::new(target))
        };
        // A tag is a snapshot of a file the agent read, so a tagged target
        // that does not exist is a wrong path, not a new file.
        if *tagged && missing_target() {
            missing.get_or_insert(written);
            continue;
        }
        if super::safe_writes::bounded_structured_file_write_target(target, home_dir, cwd)
            && !super::apply_patch_writes::protected_target(target, &workspace, cwd)
        {
            continue;
        }
        if missing_target() {
            missing.get_or_insert(written);
            continue;
        }
        return None;
    }
    Some(match missing {
        Some(path) => HashlineEdit::MissingTarget(path.to_owned()),
        None => HashlineEdit::Routine,
    })
}

/// Whether an Oh My Pi `edit` input is one plain line with no file header.
///
/// Every edit mode names its file in a `path` or `edits` field or in a header
/// line: a `[PATH#TAG]` or legacy `¶` hashline header, or a `***` patch or
/// sloppy-edit line. Oh My Pi refuses a hashline edit whose first line is not
/// a header ("input must begin with \"[PATH#HASH]\""), and a single line has
/// no room for both a header and content. Models send such calls when they
/// mean another tool, such as a path they meant to read or a command they
/// meant to run, so the call cannot change a file. Only `input` and a numeric
/// `timeout` may be present.
pub(super) fn headerless_edit(input: &serde_json::Map<String, serde_json::Value>) -> bool {
    let keys = input.iter().all(|(key, value)| match key.as_str() {
        "input" => value.is_string(),
        "timeout" => value.is_number(),
        _ => false,
    });
    let Some(line) = input.get("input").and_then(serde_json::Value::as_str) else {
        return false;
    };
    keys && line.len() <= crate::MAX_COMMAND_BYTES
        && !line.contains(['\n', '\r', '\0', '[', ']', '*', '\u{b6}'])
}

#[cfg(test)]
#[path = "omp_hashline_writes_tests.rs"]
mod tests;
