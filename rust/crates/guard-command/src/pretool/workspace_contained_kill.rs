//! `kill` forms the workspace sandbox can contain. A job specification names
//! a job of the shell that runs the command, so `npm run dev & ... kill %1`
//! stops only what this command started and reaches no other process on the
//! host. A pid operand names any process the user can signal, including a
//! daemon this session knows nothing about, so it keeps its review.
//!
//! Signal 0 is the exception a pid operand survives: the kernel performs the
//! permission check and delivers nothing, so `kill -0 4821` answers whether a
//! process is still there and leaves it running. A script that waits on a
//! server it started asks that question on every iteration, and reviewing it
//! would stop work that reaches no process at all.

/// Whether `arguments` (after `kill`) name only the shell's own jobs.
///
/// `kill` reads a signal only in its first word. Every word after that is an
/// operand, so the `-1` in `kill -9 -1 %1` is the pid that signals every
/// process the user can reach, and the `-4821` in `kill -9 -4821 %1` is a
/// process group. Reading them as options would have let both run beside a
/// job specification with no review at all.
pub(super) fn jobs_only(arguments: &[String]) -> bool {
    let mut words = arguments.iter();
    let mut jobs = 0;
    let mut first = true;
    while let Some(word) = words.next() {
        if std::mem::take(&mut first) {
            // `-s TERM` and `-n 9` carry the signal in the next word.
            if word == "-s" || word == "-n" {
                if words.next().is_none() {
                    return false;
                }
                continue;
            }
            // `--` ends the options without naming a signal.
            if word == "--" {
                continue;
            }
            if let Some(signal) = word.strip_prefix('-') {
                if !signal_name(signal) {
                    return false;
                }
                continue;
            }
        }
        if !job(word) {
            return false;
        }
        jobs += 1;
    }
    jobs > 0
}

/// Whether `arguments` (after `kill`) ask only whether the processes they
/// name are still alive.
///
/// The signal has to be exactly `0`, written as `-0`, `-s 0` or `-n 0`; a
/// name such as `SIGNULL` is not portable enough to read as the same thing.
/// Each operand is then a plain decimal pid or one of the shell's own jobs.
/// A negative operand keeps its review: `kill -0 -1` asks about every process
/// the user can reach, which is a survey of the host rather than a wait on a
/// process this session started.
pub(super) fn liveness_only(arguments: &[String]) -> bool {
    let mut words = arguments.iter();
    let Some(first) = words.next() else {
        return false;
    };
    match first.as_str() {
        "-0" => {}
        "-s" | "-n" => {
            if words.next().map(String::as_str) != Some("0") {
                return false;
            }
        }
        _ => return false,
    }
    let mut operands = 0;
    for word in words {
        if !pid(word) && !job(word) {
            return false;
        }
        operands += 1;
    }
    operands > 0
}

/// A pid operand written as plain decimal digits, naming one process. `0`
/// asks about the caller's own process group and `-1` about every process the
/// user can reach, so neither is the wait on a named process this form reads;
/// a leading zero writes the same two as `00` and `-01`.
fn pid(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('0')
        && word.chars().all(|character| character.is_ascii_digit())
}

/// A signal written against the first word: `9`, `TERM` or `SIGTERM`. `-l`
/// and `-L` list signal names and reach no process, but they also name no
/// job, so they are not this form.
fn signal_name(signal: &str) -> bool {
    !signal.is_empty()
        && !signal.starts_with(['l', 'L'])
        && signal
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

/// A job specification: `%1`, `%%`, `%+`, `%-`, `%vite` or `%?build`. A name
/// built from an expansion names whatever that holds, which this text does
/// not show.
fn job(word: &str) -> bool {
    let Some(specification) = word.strip_prefix('%') else {
        return false;
    };
    if matches!(specification, "" | "%" | "+" | "-") {
        return true;
    }
    let name = specification.strip_prefix('?').unwrap_or(specification);
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}
