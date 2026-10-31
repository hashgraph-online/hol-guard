//! The inert prefix the contained sink plans behind.
//!
//! `CI=1 command bun run build` runs `bun run build` with one setting the
//! build reads for itself. The sink is handed the program native authority
//! judged, so the split that finds it is read here rather than kept a second
//! time beside the sink: the names that stand transparently in front of a
//! program live in [`crate::parser_wrappers::transparent_prefix`], and the
//! settings a run may carry live in
//! [`crate::command_compatibility::environment::inert_environment_name`].

#[cfg(test)]
#[path = "contained_prefix_tests.rs"]
mod tests;

use crate::parser_executables::assignment_name;

/// How many prefixes one command may stack before the peel stops reading.
const PEEL_ROUNDS: usize = 16;

/// Names a dropped value would change the run under, so the peel never reads
/// one as plain data. A restricted launch forwards `PYTHONPATH` and
/// `VIRTUAL_ENV` from the caller (`forwarded_settings::forwarded_setting`), so
/// dropping the written value hands the run the caller's instead of the one
/// the command named. The rest move where the run looks for modules or writes
/// its temporary files, so a dropped value moves the run itself.
const STEERING_NAMES: &[&str] = &[
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "NODE_PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
];

/// The longest value the peel reads as plain data. A longer one is content,
/// not a setting, and the word stays in the command for the planners to judge.
const PLAIN_VALUE_LIMIT: usize = 512;

/// `NAME=value` whose name changes output or presentation and never which
/// program runs or what it loads.
fn inert_assignment(word: &str) -> Option<(&str, &str)> {
    let name = assignment_name(word)?;
    crate::command_compatibility::environment::inert_environment_name(name)
        .then(|| (name, &word[name.len() + 1..]))
}

/// Whether the word is a setting whose whole effect is a value the command
/// reads for itself, spelled plainly enough that a read-only profile's
/// environment filter would drop it before the run ever saw it. A value that
/// opens with `-` would be read as an option once the word is gone, and one
/// carrying any other character is not a plain value.
fn plain_data_setting(word: &str) -> bool {
    let Some(name) = assignment_name(word) else {
        return false;
    };
    if STEERING_NAMES.contains(&name) {
        return false;
    }
    let value = &word[name.len() + 1..];
    value.len() <= PLAIN_VALUE_LIMIT
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'.' | b'_' | b'+' | b'@' | b':' | b',' | b'%' | b'-'
                )
        })
}

/// Peel one transparent prefix, carrying the settings it holds.
///
/// Native authority owns which names stand transparently in front of a
/// program and where each one's operands end. The settings between the name
/// and the program stay the sink's business: each must be an inert assignment
/// the runner exports for the run, or, with `drop_data`, a plain-data setting
/// the read-only profile would drop anyway. A word that is neither leaves the
/// prefix in place, so the planners refuse the command rather than run its
/// program with a setting nobody filtered.
///
/// Returns how many words the prefix spans, or `None` when there is no prefix
/// here to peel.
fn transparent_step(
    rest: &[String],
    carried: &mut Vec<(String, String)>,
    drop_data: bool,
    dropped: &mut bool,
) -> Option<usize> {
    let first = rest.first()?;
    if rest.len() < 2
        || first.is_empty()
        || first.starts_with('-')
        || assignment_name(first).is_some()
    {
        return None;
    }
    let (index, _names) = crate::parser_wrappers::transparent_prefix(rest, 0)?;
    if index == 0 || index >= rest.len() {
        return None;
    }
    let mut held = Vec::new();
    let mut held_drop = false;
    for word in &rest[1..index] {
        if let Some((name, value)) = inert_assignment(word) {
            held.push((name.to_string(), value.to_string()));
        } else if drop_data && plain_data_setting(word) {
            held_drop = true;
        } else {
            return None;
        }
    }
    carried.extend(held);
    *dropped |= held_drop;
    Some(index)
}

/// Where the command's own program stands, and the settings peeled off it.
///
/// With `drop_data`, a plain-data setting (`REPORT_DIR=/tmp/r`) is dropped
/// rather than carried: callers ask for that only after the original drew a
/// contained receipt, since a read-only profile is granted only when its
/// environment filter would drop the setting, and a workspace receipt still
/// runs the original as issued. An option such as `command -v` or `env -i`
/// keeps its prefix, and any other assignment stays in the command, so the
/// core is rejected.
///
/// An assignment is read before the prefix is asked about, because a word
/// carrying `=` is no prefix name and the answer would be the same.
///
/// The third answer is whether a setting was dropped rather than carried. The
/// caller needs it to tell a core that is the command as issued from one that
/// is not: a dropped setting means the original must draw a contained receipt
/// before the core runs. It is read here so the caller need not peel the same
/// command twice to compare the two answers.
pub(crate) fn command_prefix_split(
    command: &[String],
    drop_data: bool,
) -> (usize, Vec<(String, String)>, bool) {
    let mut start = 0usize;
    let mut assignments: Vec<(String, String)> = Vec::new();
    let mut dropped = false;
    for _ in 0..PEEL_ROUNDS {
        let rest = &command[start..];
        if let Some((name, value)) = rest.first().and_then(|word| inert_assignment(word)) {
            assignments.push((name.to_string(), value.to_string()));
            start += 1;
        } else if drop_data && rest.len() > 1 && plain_data_setting(&rest[0]) {
            dropped = true;
            start += 1;
        } else if let Some(step) = transparent_step(rest, &mut assignments, drop_data, &mut dropped)
        {
            start += step;
        } else {
            break;
        }
    }
    (start, assignments, dropped)
}
