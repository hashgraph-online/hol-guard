//! `head` and `tail`: the option grammar both share, and the operand
//! proof each target meets. Split out of `safe_reads.rs` so the file that
//! holds the other read provers stays readable.

use super::{command_read_target, MAX_PLAIN_FILE_TARGETS};

/// `head -n 3 a b` prints what `head -n 3 a; head -n 3 b` prints, with a
/// `==> a <==` line before each, so every operand gets the single-file proof
/// that `cat a b` gives its operands, up to the same bound.
///
/// `follow` is set for `tail`, the only one of the two that takes `-f`. The
/// flag changes when the program stops reading, not what it reads: it keeps
/// the same descriptor open and prints what is appended to it. `head` has no
/// such option, so the spelling stays unproven there.
pub(in crate::pretool) fn safe_head_tail_arguments(
    arguments: &[String],
    piped_input: bool,
    context: crate::pretool::PathContext<'_>,
    follow: bool,
) -> bool {
    safe_head_tail_with_targets(arguments, piped_input, context, true, follow)
}

pub(in crate::pretool) fn safe_head_tail_stdin_arguments(arguments: &[String]) -> bool {
    safe_head_tail_with_targets(
        arguments,
        true,
        crate::pretool::PathContext::default(),
        false,
        false,
    )
}

/// A `tail` option that keeps reading the file this proof checked: `-f` and
/// its long spellings. The descriptor stays open, so what is printed is what
/// is appended to the same file, and nothing is written, moved or truncated.
///
/// The name-following spellings -- `-F`, `--follow=name` and `--retry` -- are
/// deliberately absent. They re-resolve the path after the proof read it, and
/// reopen whatever the name points at later: a rotation, a replacement, or a
/// symlink planted by another process into a world-writable directory. The
/// single-file proof admits operands that do not exist yet, so a name-follow
/// would wait for one to appear and then stream a file the proof never saw.
/// Only the descriptor this proof checked is proven here.
///
/// The options that take a value -- `--pid` and `--sleep-interval` -- are left
/// out too, so a value is never read here as one of these.
fn follow_option(argument: &str) -> bool {
    matches!(argument, "-f" | "--follow" | "--follow=descriptor")
}

/// A head/tail count: `20`, or `+31` for "from line 31" (`tail -n +31`).
fn head_tail_count(value: &str) -> bool {
    let digits = value.strip_prefix('+').unwrap_or(value);
    !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn safe_head_tail_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: crate::pretool::PathContext<'_>,
    allow_target: bool,
    follow: bool,
) -> bool {
    let mut targets = 0usize;
    let mut expect_count = false;
    let mut after_options = false;
    let mut following = false;
    for argument in arguments {
        if expect_count {
            if !head_tail_count(argument) {
                return false;
            }
            expect_count = false;
            continue;
        }
        if after_options {
            if !allow_target || argument == "-" || !command_read_target(argument, context, false) {
                return false;
            }
            targets += 1;
            continue;
        }
        if argument == "--" {
            after_options = true;
            continue;
        }
        if matches!(argument.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
            expect_count = true;
            continue;
        }
        if follow && follow_option(argument) {
            following = true;
            continue;
        }
        if let Some(value) = argument
            .strip_prefix("--lines=")
            .or_else(|| argument.strip_prefix("--bytes="))
        {
            if !head_tail_count(value) {
                return false;
            }
            continue;
        }
        // `-20`, and the attached `-n+31` and `-c10` spellings.
        if let Some(value) = argument.strip_prefix('-') {
            if value.strip_prefix(['n', 'c']).is_some_and(head_tail_count)
                || (!value.starts_with('+') && head_tail_count(value))
            {
                continue;
            }
        }
        // A bare `+N` before `--` is a file name to `head` but, with one
        // file beside it, GNU `tail`'s old spelling of `-n +N`, which also
        // takes a trailing `f` to follow. Neither reading is proven here;
        // `-n +N` remains an option/value pair above.
        if argument.starts_with(['-', '+']) {
            return false;
        }
        if !allow_target || !command_read_target(argument, context, false) {
            return false;
        }
        targets += 1;
    }
    // Following a named file prints what is appended to it and ends when the
    // session ends. Following standard input is a different command: the
    // producer's end closes nothing, so the pipeline never finishes and the
    // session's shell is held open on a read nothing will complete. That
    // spelling stays unproven, as it was before `tail` learned to follow here.
    if following && targets == 0 {
        return false;
    }
    targets <= MAX_PLAIN_FILE_TARGETS && (targets > 0 || piped_input) && !expect_count
}

#[cfg(test)]
#[path = "safe_reads_head_tail_tests.rs"]
mod head_tail_tests;
