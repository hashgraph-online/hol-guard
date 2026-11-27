//! Path operands that name nothing for `grep` to read.
//!
//! A missing operand only prints an error (`super::absent_target`). A glob
//! that matches nothing is the same: `grep -rn KEY README.md src/config*`
//! with no `src/config*` hands `grep` the literal word under bash, which
//! names no file, and fails the command under zsh's `nomatch`. Under
//! `nullglob` the word disappears instead. Without `-r`, `grep` then reads
//! its other operands or standard input. With `-r` and no operand left it
//! would walk the working directory, so a recursive search counts an
//! unmatched glob beside a root that is still there to be proven or missing,
//! or on its own when the working directory itself is a proven root:
//! `grep -rn KEY *.ts` in a folder whose `.ts` files sit in subdirectories
//! reads no more than `grep -rn KEY .` there.

use super::{tree, ReadContext};

/// A path operand that is missing, or a glob no shell option can match.
pub(super) fn missing_operand(value: &str, context: ReadContext<'_>) -> bool {
    super::absent_target(value, context) || unmatched_glob(value, context)
}

/// A `*` or `?` glob, outside any bracket class, that the strict expansion
/// proves matches nothing in a real directory, or that sits below a directory
/// that is not there. A `~` glob counts only while the shell's home is the
/// declared one.
fn unmatched_glob(value: &str, context: ReadContext<'_>) -> bool {
    value.contains(['*', '?'])
        && !value.contains(['[', ']'])
        && (!value.starts_with('~') || context.shell_home_matches)
        && (tree::safe_unmatched_glob_operand(value, context, false)
            || below_absent_directory(value, context))
}

/// `tools/*.py` with no `tools`: no shell option makes a pattern match below
/// a directory that does not exist, as `grep -rn KEY src/*.py tools/*.py`
/// shows when an agent searches a fixed list of places. The literal directory
/// before the first pattern component has to clear the rule a missing literal
/// root clears, so a credential store stays refused. An extended-glob group
/// such as `+(a)` can match a real directory, so a parenthesis keeps the
/// review.
fn below_absent_directory(value: &str, context: ReadContext<'_>) -> bool {
    let first_pattern = value.find(['*', '?']).unwrap_or(value.len());
    value[..first_pattern]
        .rsplit_once('/')
        .is_some_and(|(directory, _)| {
            !directory.is_empty()
                && !directory.contains(['(', ')'])
                && super::absent_target(directory, context)
        })
}

/// Every recursive root is proven or missing (`grep -rn x src tests` with no
/// `tests`, and `grep -rn x <absent>` on its own): a root that is not there
/// opens nothing, so the walk reads no file. With no operand at all `grep -r`
/// walks the working directory instead, so when `nullglob` could remove
/// every root the working directory must itself be a proven root.
pub(super) fn recursive_targets_proven(
    targets: &[&str],
    proven: impl Fn(&str) -> bool,
    context: ReadContext<'_>,
    absent: bool,
) -> bool {
    let absent = absent.then_some(context);
    let mut kept = false;
    for &target in targets {
        if proven(target) || absent.is_some_and(|context| super::absent_target(target, context)) {
            kept |= !dropped_by_nullglob(target, context);
        } else if !absent.is_some_and(|context| unmatched_glob(target, context)) {
            return false;
        }
    }
    kept || (!targets.is_empty() && proven("."))
}

/// A bracket class that matches nothing is searched as the literal path it
/// spells, as in `grep -rn x app/[slug]`, but `nullglob` removes the word
/// instead. A `*` or `?` glob that matches only under some shell options,
/// such as `tests/**/.` with only a `tests` directory, which needs
/// `globstar`, is removed the same way without them. Unless the quote map
/// shows the word quoted, such a word keeps no root, and the working
/// directory a bare `grep -r` would walk has to be proven too.
fn dropped_by_nullglob(target: &str, context: ReadContext<'_>) -> bool {
    if context.literal_words.iter().any(|word| word == target) {
        return false;
    }
    if target.contains('[') {
        return tree::inert_bracket_class(target, context);
    }
    target.contains(['*', '?']) && !tree::glob_surely_matches(target, context)
}
