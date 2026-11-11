//! An `--exclude` or `--exclude-dir` written after the pattern or a path, as
//! in `grep -rln needle src --exclude-dir=fixtures`.
//!
//! GNU and BSD grep permute their arguments, so the option still prunes the
//! walk there. With `POSIXLY_CORRECT` set, GNU grep stops reading options at
//! the first operand and takes the word as one more path instead. The proof
//! has to hold under both readings, so a late exclusion is never counted as
//! narrowing the walk: the operands must be safe to search in full. And the
//! word itself must name nothing grep could open, which holds when no entry
//! in the working directory starts with `--exclude`. That also leaves a
//! wildcard in the value nothing to expand to.
//!
//! The separated spelling (`--exclude-dir NAME`) would turn `NAME` into an
//! operand under the second reading, so it keeps its review.

use std::path::Path;

const PREFIX: &[u8] = b"--exclude";

/// Whether a late `--exclude=VALUE` or `--exclude-dir=VALUE` can be left out
/// of the proof. `unplanted` says no other segment of the command can create
/// a file before `grep` runs.
pub(super) fn inert(argument: &str, context: super::ReadContext<'_>, unplanted: bool) -> bool {
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
