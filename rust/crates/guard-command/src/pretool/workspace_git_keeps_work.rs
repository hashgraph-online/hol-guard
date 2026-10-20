//! Git workspace commands that cannot lose uncommitted work.
//!
//! `switch`, `checkout` and `stash` stay out of the sandbox because most of
//! their forms overwrite files the sandbox cannot restore. Three spellings
//! leave every change reachable: creating a branch at `HEAD` keeps the working
//! tree as it is, and a plain stash push records the changes in `refs/stash`,
//! where `git stash pop` brings them back. Start points, pathspecs, force and
//! merge options, and the stash subcommands that drop or apply entries keep
//! their review.
use crate::CanonicalCommandV1;
use guard_contracts::NativeCommandObservationV1;

const RULES: &[&str] = &[
    "command.git.switch",
    "command.git.checkout",
    "command.git.stash",
];

/// Whether `observation` is one of the rules above and every segment it
/// matched is a form that keeps uncommitted work.
pub(super) fn keeps_work(
    observation: &NativeCommandObservationV1,
    model: &CanonicalCommandV1,
) -> bool {
    if !RULES.contains(&observation.rule_id.as_str()) {
        return false;
    }
    let mut indexes = observation
        .matcher_evidence
        .iter()
        .map(|evidence| evidence.segment_index)
        .chain(observation.effective_segment_indexes.iter().copied())
        .peekable();
    indexes.peek().is_some()
        && indexes.all(|index| {
            model.segments.get(index).is_some_and(|segment| {
                segment.executable.as_deref() == Some("git")
                    && keeping_arguments(&segment.arguments)
            })
        })
}

/// `switch -c NAME`, `checkout -b NAME`, or `stash [push] [-q] [-u] [-m MSG]`.
/// Leading Git options such as `-c` or `-C` are refused: they can point the
/// command at another repository or configuration.
pub(in crate::pretool) fn keeping_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["switch", "-c" | "--create", name] | ["checkout", "-b", name] => branch_name(name),
        ["stash", rest @ ..] => stash_push(rest.strip_prefix(&["push"]).unwrap_or(rest)),
        _ => false,
    }
}

fn stash_push(mut options: &[&str]) -> bool {
    while let Some((first, rest)) = options.split_first() {
        options = match *first {
            "-q" | "--quiet" | "-u" | "--include-untracked" => rest,
            "-m" | "--message" => match rest.split_first() {
                Some((_, after)) => after,
                None => return false,
            },
            value if value.starts_with("--message=") => rest,
            _ => return false,
        };
    }
    true
}

fn branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.starts_with(['-', '/', '.'])
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}
