//! Git workspace commands that cannot lose uncommitted work.
//!
//! `switch`, `checkout`, `stash`, `reset` and `restore` stay out of the sandbox
//! because most of their forms overwrite files the sandbox cannot restore. A
//! few spellings leave every change reachable: creating a branch at `HEAD`
//! keeps the working tree as it is, a stash push records the changes in
//! `refs/stash`, where `git stash pop` brings them back — named paths included,
//! since a pathspec keeps strictly less work than the bare form and the entry
//! still holds every change it moves — and `reset --soft`, `reset --mixed` and
//! `restore --staged` move `HEAD` and the index while the working tree keeps
//! every byte it had. Start points, force and merge options, a pathspec given
//! to anything but `stash push`, the stash subcommands that drop or apply
//! entries, and every form that writes the working tree — `reset --hard`,
//! `--merge` and `--keep`, and `restore` without `--staged` or with
//! `--worktree` — keep their review.
use crate::CanonicalCommandV1;
use guard_contracts::NativeCommandObservationV1;

const RULES: &[&str] = &[
    "command.git.switch",
    "command.git.checkout",
    "command.git.stash",
    "command.git.reset",
    "command.git.restore",
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

/// `switch -c NAME`, `checkout -b NAME`,
/// `stash [push] [-q] [-u] [-k|-S] [-m MSG] [--] [PATH...]`,
/// `reset [-q] [--soft|--mixed] [REV] [-- PATH...]`, or
/// `restore --staged [-q] [--] PATH...`. Leading Git options such as `-c` or
/// `-C` are refused: they can point the command at another repository or
/// configuration.
pub(in crate::pretool) fn keeping_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["switch", "-c" | "--create", name] | ["checkout", "-b", name] => branch_name(name),
        ["stash", rest @ ..] => match rest.strip_prefix(&["push"]) {
            Some(after) => stash_push(after, true),
            None => stash_push(rest, false),
        },
        ["reset", rest @ ..] => index_only_reset(rest),
        ["restore", rest @ ..] => index_only_restore(rest),
        _ => false,
    }
}

/// `git stash [push]` with the options that only choose how much of the
/// working tree moves into the entry, and the pathspecs that narrow it to
/// named paths. A pathspec keeps strictly less work than the unbounded form
/// does, and Git resolves it inside the repository, so the stash entry still
/// holds every change the command moves. `--keep-index` and `--staged` leave
/// more behind, not less. An unread option is refused.
///
/// `pushed` records whether the caller spelled `push` out. Without it a bare
/// word is a subcommand, not a pathspec — `git stash drop` discards an entry,
/// and Git itself refuses to assume `push` for it — so only an explicit `--`
/// introduces pathspecs there.
fn stash_push(mut options: &[&str], pushed: bool) -> bool {
    while let Some((first, rest)) = options.split_first() {
        options = match *first {
            "-q" | "--quiet" | "-u" | "--include-untracked" => rest,
            "-k" | "--keep-index" | "--no-keep-index" | "-S" | "--staged" => rest,
            "-m" | "--message" => match rest.split_first() {
                Some((_, after)) => after,
                None => return false,
            },
            value if value.starts_with("--message=") => rest,
            "--" => return operands(rest),
            _ => return pushed && operands(options),
        };
    }
    true
}

/// `git reset` without a working-tree mode: `--soft` moves `HEAD` alone and
/// `--mixed` (the default) also rewrites the index, and both leave every
/// tracked file in the working tree exactly as it was. `--hard`, `--merge`,
/// `--keep` and the interactive `--patch` overwrite files, so they are not here.
fn index_only_reset(arguments: &[&str]) -> bool {
    let mut options = arguments;
    let mut mode = false;
    while let Some((first, rest)) = options.split_first() {
        options = match *first {
            "-q" | "--quiet" => rest,
            "--soft" | "--mixed" if !mode => {
                mode = true;
                rest
            }
            "--" => return operands(rest),
            value if value.starts_with('-') => return false,
            _ => return operands(options),
        };
    }
    true
}

/// `git restore --staged PATH...` replaces index entries from `HEAD`; the
/// working tree is untouched, and the replaced blobs stay in the object store.
/// Without `--staged`, and with `--worktree`, `restore` overwrites files, so
/// those forms are not here. `--source` and `--patch` are refused as unknown.
fn index_only_restore(arguments: &[&str]) -> bool {
    let mut options = arguments;
    let mut staged = false;
    while let Some((first, rest)) = options.split_first() {
        options = match *first {
            "-q" | "--quiet" => rest,
            "-S" | "--staged" => {
                staged = true;
                rest
            }
            "--" => return staged && !rest.is_empty() && operands(rest),
            value if value.starts_with('-') => return false,
            _ => return staged && operands(options),
        };
    }
    false
}

/// Whether every remaining word is an operand rather than an option, allowing
/// one `--` separator between the revision and the pathspecs. A revision or
/// pathspec that starts with `-` is refused as unread.
fn operands(words: &[&str]) -> bool {
    let mut separated = false;
    for word in words {
        if *word == "--" && !separated {
            separated = true;
            continue;
        }
        if word.is_empty() || word.starts_with('-') {
            return false;
        }
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

#[cfg(test)]
#[path = "workspace_git_keeps_work_tests.rs"]
mod tests;
