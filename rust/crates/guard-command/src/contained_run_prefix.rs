//! The prefixes a contained run stands behind, and the clock that bounds it.
//!
//! `nice -n 10 timeout 20 pytest -q` runs `pytest -q` for twenty seconds. A
//! system `timeout` bounds how long the work may take and not what it may do,
//! and the launchers the parser reads set scheduling, buffering or the shell's
//! own `exec`, so the program behind them is the program native authority
//! judged. The contained planners are handed that program, and the clock is
//! reported back so the run it was peeled from is still bounded.
//!
//! The names that launch a program live in
//! [`crate::parser_wrappers::launcher_program`], the duration grammar in
//! [`crate::parser_wrappers::clock_seconds`], and the inert prefix split in
//! [`crate::contained_prefix`], so one peel reads a command once.

#[cfg(test)]
#[path = "contained_run_prefix_tests.rs"]
mod tests;

use crate::parser_executables::assignment_name;
use crate::parser_wrappers::{clock_seconds, trusted_timeout};

/// How many prefixes one command may stack before the peel stops reading.
const PEEL_ROUNDS: usize = 4;

/// A local file path with a `node_modules` component: an installed package's
/// own entrypoint, which `bun` and `node` both start as the script it names.
/// An option, a remote URL and the directory itself are not an entrypoint.
pub(crate) fn installed_entry(entry: &str) -> bool {
    let entry = entry.replace('\\', "/");
    !entry.starts_with('-')
        && !entry.contains("://")
        && !entry.ends_with('/')
        && entry.split('/').any(|part| part == "node_modules")
}

/// Where the program stands behind every system `timeout <duration>` prefix,
/// and the tightest clock those prefixes set.
///
/// A duration of zero turns `timeout` off: the prefix is still peeled and the
/// run it names is left unbounded rather than cut to a second.
fn timeout_clock(command: &[String], seconds: &mut Option<u64>) -> usize {
    let mut start = 0usize;
    for _ in 0..PEEL_ROUNDS {
        if command.len() - start < 3 || !trusted_timeout(&command[start]) {
            break;
        }
        let mut at = start + 1;
        if command[at] == "--" {
            at += 1;
        }
        if command.len() - at < 2 {
            break;
        }
        let Some(clock) = clock_seconds(&command[at]) else {
            break;
        };
        let program = &command[at + 1];
        if program.is_empty() || program.starts_with('-') || assignment_name(program).is_some() {
            break;
        }
        if clock > 0 {
            *seconds = Some(seconds.map_or(clock, |held| held.min(clock)));
        }
        start = at + 1;
    }
    start
}

/// Where the program a launcher runs stands, or `0` when this command names
/// no launcher. A launcher stands as a bare name in front of a program, so a
/// command too short to hold both, or one whose first word is spelled as a
/// path, is not one and is not read as one.
fn launcher_start(command: &[String]) -> usize {
    if command.len() < 2 || command[0].is_empty() || command[0].contains(['/', '\\']) {
        return 0;
    }
    match crate::parser_wrappers::launcher_program(command, 0) {
        Some(index) if index > 0 && index < command.len() => index,
        _ => 0,
    }
}

/// `bun <dir>/node_modules/<package>/<entry>` spelled as the run `node` names.
///
/// Bun reads a file operand as the script to run, so an installed package's
/// entrypoint is the program Node starts on the same file, and the planners
/// run it on the project's Node image as they run `bun x vite build`. An
/// option, a remote URL or any other operand keeps the command as written.
fn bun_entry_as_node(command: &[String]) -> Vec<String> {
    if command.len() < 2
        || crate::program_basename(&command[0]) != "bun"
        || !installed_entry(&command[1])
    {
        return command.to_vec();
    }
    let mut spelled = command.to_vec();
    spelled[0] = "node".to_owned();
    spelled
}

/// The program the contained planners are handed, and the seconds that bound
/// the run, or `None` when nothing bounds it.
///
/// Each peeled prefix is followed by the inert `command`/`env` prefix and
/// assignment split the planners already receive, so `nice -n 10 env CI=1
/// timeout 20 pytest -q` reaches them as the `pytest -q` it runs.
pub(crate) fn run_prefix_peel(command: &[String]) -> (Vec<String>, Option<u64>) {
    let mut current = command.to_vec();
    let mut seconds = None;
    for _ in 0..PEEL_ROUNDS {
        let timed = timeout_clock(&current, &mut seconds);
        let launched = timed + launcher_start(&current[timed..]);
        if launched == 0 {
            break;
        }
        let peeled = &current[launched..];
        let (core, _assignments, _dropped) =
            crate::contained_prefix::command_prefix_split(peeled, false);
        current = peeled[core..].to_vec();
    }
    (bun_entry_as_node(&current), seconds)
}
