//! `--exclude` and `--exclude-dir`, wherever they appear in a `grep` command.
//!
//! An exact name excluded before the first operand prunes the walk and is part
//! of the proof. Any other value only narrows what grep reads, so the operands
//! must be safe to search without it.
//!
//! A value holding `$` or a backtick keeps the review. The shell expands it
//! before grep runs, and word splitting can hand grep extra operands the proof
//! never checked: with `X='fixtures .env'`, `--exclude-dir=$X` also searches
//! `.env`.
//!
//! GNU grep includes a file that matches neither list when an `--exclude`
//! comes before the first `--include`, so any `--exclude` beside an
//! `--include` keeps the review.
//!
//! An exclusion written after the pattern or a path, as in
//! `grep -rln needle src --exclude-dir=fixtures`, is read twice. GNU and BSD
//! grep permute their arguments, so the option still prunes the walk there.
//! With `POSIXLY_CORRECT` set, GNU grep stops reading options at the first
//! operand and takes the word as one more path instead. The proof has to hold
//! under both readings, so a late exclusion is never counted as narrowing the
//! walk. The word itself must name nothing grep could open, which holds when no
//! entry in the working directory starts with `--exclude`. That also leaves a
//! wildcard in the value nothing to expand to. The separated late spelling
//! (`--exclude-dir NAME`) would turn `NAME` into an operand under the second
//! reading, so it keeps its review.

use std::path::Path;

const PREFIX: &[u8] = b"--exclude";

/// The exclusions a `grep` command names.
#[derive(Default)]
pub(super) struct Exclusions<'a> {
    /// Exact names left out of the walk, from the options before the operands.
    pub(super) files: Vec<&'a str>,
    pub(super) directories: Vec<&'a str>,
    /// Set after a separated `--exclude NAME` or `--exclude-dir NAME`, whose
    /// value is the next argument.
    pending: Option<bool>,
    /// Any `--exclude`, in any position and with any value.
    file_seen: bool,
}

impl<'a> Exclusions<'a> {
    /// Reads `argument` as the value of a separated exclusion. `None` when no
    /// exclusion is waiting for one; otherwise whether the value is proven.
    pub(super) fn take_value(&mut self, argument: &'a str) -> Option<bool> {
        let directory = self.pending.take()?;
        if argument.is_empty() || expands(argument) {
            return Some(false);
        }
        self.record(directory, argument);
        Some(true)
    }

    /// Reads a long option. `None` when it is not an exclusion; otherwise
    /// whether it is proven. `late` says an operand came before it, and
    /// `unplanted` that no other segment can create a file before grep runs.
    pub(super) fn option(
        &mut self,
        argument: &'a str,
        late: bool,
        context: super::ReadContext<'_>,
        unplanted: bool,
    ) -> Option<bool> {
        let (name, attached) = argument.split_once('=').unwrap_or((argument, ""));
        if !matches!(name, "--exclude" | "--exclude-dir") {
            return None;
        }
        let directory = name == "--exclude-dir";
        self.file_seen |= !directory;
        if expands(argument) {
            return Some(false);
        }
        if late {
            return Some(inert(argument, context, unplanted));
        }
        if !attached.is_empty() {
            self.record(directory, attached);
        } else if argument.contains('=') {
            return Some(false);
        } else {
            self.pending = Some(directory);
        }
        Some(true)
    }

    /// A separated exclusion is still waiting for its value.
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Whether an `--include` list can be read as the whole walk: no
    /// exclusion could change which files it selects.
    pub(super) fn leave_includes_exact(&self) -> bool {
        self.files.is_empty() && self.directories.is_empty() && !self.file_seen
    }

    fn record(&mut self, directory: bool, value: &'a str) {
        if !exact(value) {
            return;
        }
        if directory {
            self.directories.push(value);
        } else {
            self.files.push(value);
        }
    }
}

/// A parameter, command substitution or arithmetic expansion.
fn expands(value: &str) -> bool {
    value.contains(['$', '`'])
}

fn exact(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Whether a late `--exclude=VALUE` or `--exclude-dir=VALUE` can be left out
/// of the proof.
fn inert(argument: &str, context: super::ReadContext<'_>, unplanted: bool) -> bool {
    let Some((_, value)) = argument.split_once('=') else {
        return false;
    };
    if value.is_empty() || !unplanted {
        return false;
    }
    let Some(cwd) = context.cwd.map(Path::new).filter(|cwd| cwd.is_absolute()) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return false;
    };
    // Compared without case: a case-insensitive volume opens `--EXCLUDE=x`
    // for the operand `--exclude=x`.
    entries.into_iter().all(|entry| {
        entry.is_ok_and(|entry| {
            let name = entry.file_name();
            let name = name.as_encoded_bytes();
            !(name.len() >= PREFIX.len() && name[..PREFIX.len()].eq_ignore_ascii_case(PREFIX))
        })
    })
}
