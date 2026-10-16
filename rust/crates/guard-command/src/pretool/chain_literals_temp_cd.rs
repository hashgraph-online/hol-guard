//! `cd "$(mktemp -d)" && node ../src/cli.js list` moves into a fresh scratch
//! directory. The workspace sandbox launches its shell with `TMPDIR` set to
//! the run's private writable directory, and `mktemp -d` with no template, or
//! with `-t TEMPLATE`, creates its directory there on GNU and BSD alike.
//!
//! When every substitution is such a directory and is the whole operand of a
//! `cd` or `pushd`, the sandbox launcher judges the command with the stand-in
//! in its place and runs the raw text, so the real `mktemp` runs inside the
//! sandbox. Outside the sandbox nothing changes: the stand-in still names
//! the absent root, never `$TMPDIR`.

use super::{project as with_stand_ins, stand_in, TEMPORARY_ROOT, TEMPORARY_VALUE};
use crate::shell_structure::extract_command_substitution_spans;

/// List operators around a `cd` that runs as a command of its own.
const SEPARATORS: [&str; 3] = ["&&", "||", ";"];

/// The raw command with each substitution written as the temporary stand-in;
/// `None` unless every substitution is a private temporary directory that is
/// the whole operand of a `cd` or `pushd` run as its own command. The shared
/// projection still refuses `..` and any mention of `TMPDIR`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn project(command: &str) -> Option<String> {
    let projected = with_stand_ins(command, private_temporary_directory)?;
    let chars: Vec<char> = command.chars().collect();
    extract_command_substitution_spans(command)
        .iter()
        .all(|substitution| entered(&chars, substitution.start, substitution.end))
        .then_some(projected)
}

/// Whether a `cd` operand is the stand-in for a fresh private temporary
/// directory. Its root must be absent, so a literal spelling of the stand-in
/// can only fail to change directory.
pub(crate) fn private_directory(target: &str) -> bool {
    target == TEMPORARY_VALUE && std::fs::symlink_metadata(TEMPORARY_ROOT).is_err()
}

/// How many times `text` names the stand-in's root.
pub(crate) fn mentions(text: &str) -> usize {
    text.matches(TEMPORARY_ROOT).count()
}

/// `mktemp -d`, optionally with `-q` and one `-t TEMPLATE`. The template is
/// taken only right after the group that ends in `t`, where BSD reads it as
/// that option's prefix under `TMPDIR` and GNU as a name under `TMPDIR`;
/// without `-t` a template names a path below the working directory.
fn private_temporary_directory(body: &str) -> bool {
    if stand_in(body) != Some(TEMPORARY_VALUE) {
        return false;
    }
    let (mut directory, mut template_next) = (false, false);
    for word in body.split(' ').filter(|word| !word.is_empty()).skip(1) {
        match word.strip_prefix('-') {
            Some(flags) if !template_next && flags.matches('t').count() <= 1 => {
                if flags.contains('t') && !flags.ends_with('t') {
                    return false;
                }
                directory |= flags.contains('d');
                template_next = flags.ends_with('t');
            }
            None if template_next => template_next = false,
            _ => return false,
        }
    }
    directory && !template_next
}

/// Whether the substitution at character span `start..end`, bare or exactly
/// double-quoted, is the only operand of a `cd` or `pushd` that starts a list
/// item and ends it.
fn entered(chars: &[char], start: usize, end: usize) -> bool {
    let quoted = start > 0 && chars.get(start - 1) == Some(&'"') && chars.get(end) == Some(&'"');
    let (start, end) = if quoted {
        (start - 1, end + 1)
    } else {
        (start, end)
    };
    let (Some(before), Some(after)) = (chars.get(..start), chars.get(end..)) else {
        return false;
    };
    let (before, after): (String, String) = (before.iter().collect(), after.iter().collect());
    let Some(head) = before.strip_suffix([' ', '\t']) else {
        return false;
    };
    let head = head.trim_end_matches([' ', '\t']);
    let Some(head) = head
        .strip_suffix("pushd")
        .or_else(|| head.strip_suffix("cd"))
    else {
        return false;
    };
    let (head, after) = (
        head.trim_end_matches([' ', '\t']),
        after.trim_start_matches([' ', '\t']),
    );
    (head.is_empty()
        || SEPARATORS
            .iter()
            .any(|&separator| head.ends_with(separator)))
        && (after.is_empty()
            || SEPARATORS
                .iter()
                .any(|&separator| after.starts_with(separator)))
}

#[cfg(test)]
#[path = "chain_literals_temp_cd_tests.rs"]
mod tests;
