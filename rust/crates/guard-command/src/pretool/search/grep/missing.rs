//! Path operands that name nothing for `grep` to read.
//!
//! A missing operand only prints an error (`super::absent_target`). A glob
//! that matches nothing is the same: `grep -rn KEY README.md src/config*`
//! with no `src/config*` hands `grep` the literal word under bash, which
//! names no file, and fails the command under zsh's `nomatch`. Under
//! `nullglob` the word disappears instead. Without `-r`, `grep` then reads
//! its other operands or standard input. With `-r` and no operand left it
//! would walk the working directory, so a recursive search counts an
//! unmatched glob only beside a root that is still there to be proven or
//! missing.

use super::{tree, ReadContext};

/// A path operand that is missing, or a glob no shell option can match.
pub(super) fn missing_operand(value: &str, context: ReadContext<'_>) -> bool {
    super::absent_target(value, context) || unmatched_glob(value, context)
}

/// A `*` or `?` glob, outside any bracket class, that the strict expansion
/// proves matches nothing in a real directory. A `~` glob counts only while
/// the shell's home is the declared one.
fn unmatched_glob(value: &str, context: ReadContext<'_>) -> bool {
    value.contains(['*', '?'])
        && !value.contains(['[', ']'])
        && (!value.starts_with('~') || context.shell_home_matches)
        && tree::safe_unmatched_glob_operand(value, context, false)
}

/// Every recursive root is proven or missing (`grep -rn x src tests` with no
/// `tests`, and `grep -rn x <absent>` on its own): a root that is not there
/// opens nothing, so the walk reads no file. With no operand at all `grep -r`
/// walks the working directory instead, which only a proven root admits, so
/// at least one root must be one `nullglob` cannot remove.
pub(super) fn recursive_targets_proven(
    targets: &[&str],
    proven: impl Fn(&str) -> bool,
    absent: Option<ReadContext<'_>>,
) -> bool {
    let mut kept = false;
    for &target in targets {
        if proven(target) || absent.is_some_and(|context| super::absent_target(target, context)) {
            kept = true;
        } else if !absent.is_some_and(|context| unmatched_glob(target, context)) {
            return false;
        }
    }
    kept
}
