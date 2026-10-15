//! Proof for routine Oh My Pi hashline edits.
//!
//! Oh My Pi's `edit` tool takes one `input` string: an optional
//! `*** Begin Patch` line, then one `[PATH#TAG]` header per file followed by
//! `PUT`/`CUT` operations and `+` body rows, then `*** End Patch`. The body
//! rows are file content, not commands, so the edit gets the same bounded
//! proof as a Codex `apply_patch`: every header must name a file that the
//! native file write proof accepts and that is not agent instruction or VCS
//! metadata.
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
    /// fix the path rather than wait on an approval.
    MissingTarget,
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
            continue;
        }
        let operation = line.starts_with("PUT ") || line.starts_with("CUT ");
        if !in_file || !(operation || line.starts_with('+')) {
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
    let plain = !path.is_empty()
        && home_relative
        && !path.starts_with(['"', '\'', '*'])
        && !path.contains(['#', ':']);
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
    let mut missing = false;
    for (target, tagged) in &targets {
        let target = &match target.strip_prefix("~/") {
            Some(rest) => Path::new(home_dir?).join(rest).to_str()?.to_owned(),
            None => target.clone(),
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
            missing = true;
            continue;
        }
        if super::safe_writes::bounded_structured_file_write_target(target, home_dir, cwd)
            && !super::apply_patch_writes::protected_target(target, &workspace, cwd)
        {
            continue;
        }
        if missing_target() {
            missing = true;
            continue;
        }
        return None;
    }
    Some(if missing {
        HashlineEdit::MissingTarget
    } else {
        HashlineEdit::Routine
    })
}

#[cfg(test)]
#[path = "omp_hashline_writes_tests.rs"]
mod tests;
