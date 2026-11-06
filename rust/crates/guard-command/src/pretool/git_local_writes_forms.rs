//! The argument forms of the local Git writes `git_local_writes` proves:
//! `add`, a non-forced `rm`, `commit` with its message on the command line or
//! on standard input, and a non-forced `branch` rename, plus the `stash list`
//! and `stash show` reads beside them.

use super::super::git_remote_config::GitConfig;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::time::Instant;

/// Options `allowed` accepts, then pathspecs, with `--` ending the options.
fn pathspecs(rest: &[&str], allowed: impl Fn(&str) -> bool) -> bool {
    let mut options = true;
    rest.iter().all(|word| {
        if options && *word == "--" {
            options = false;
            true
        } else if options && word.starts_with('-') {
            allowed(word)
        } else {
            !word.is_empty()
        }
    })
}

pub(super) fn add(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-A" | "--all"
                | "-u"
                | "--update"
                | "-v"
                | "--verbose"
                | "-n"
                | "--dry-run"
                | "-N"
                | "--intent-to-add"
                | "--ignore-errors"
        )
    })
}

pub(super) fn rm(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-q" | "--quiet" | "-r" | "--cached" | "-n" | "--dry-run" | "--ignore-unmatch"
        )
    })
}

/// A commit whose message is on the command line or on standard input, so no
/// editor starts.
pub(super) fn commit(rest: &[&str]) -> bool {
    commit_form(rest).is_some()
}

/// Whether a `git commit` segment asks Git to sign the commit, which starts
/// the configured signing program (`git_local_writes_signing`).
pub(super) fn signs(segment: &CommandSegmentV1) -> bool {
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    matches!(words.split_first(), Some((&"commit", rest)) if commit_form(rest) == Some(true))
}

/// `Some(signs)` for a commit form the proof accepts. An author or a reset
/// author only changes the commit's metadata; `-S` and `--gpg-sign` (with an
/// attached key) start the signing program, which the caller must prove.
/// Short options may be clustered as Git allows: `-qm msg`, `-am msg`.
pub(super) fn commit_form(rest: &[&str]) -> Option<bool> {
    let form = commit_options(rest)?;
    (form.message || (form.amend && form.no_edit)).then_some(form.signs)
}

/// Whether the commit reads its message from standard input, which is the only
/// commit form that consumes the bytes a heredoc in front of it supplies.
/// `-m`, a message file and an amended message all leave those bytes unread,
/// so a projection that dropped the body would describe a command the shell
/// never ran.
pub(crate) fn message_from_standard_input(rest: &[&str]) -> bool {
    commit_options(rest).is_some_and(|form| form.standard_input)
}

/// What the option scan found. `message` covers every spelling that supplies
/// one; `standard_input` narrows that to the spellings that read it from
/// standard input.
struct CommitOptions {
    message: bool,
    standard_input: bool,
    amend: bool,
    no_edit: bool,
    signs: bool,
}

fn commit_options(rest: &[&str]) -> Option<CommitOptions> {
    let (mut message, mut amend, mut no_edit, mut signs) = (false, false, false, false);
    let mut standard_input = false;
    let mut options = true;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if !options || !word.starts_with('-') {
            if word.is_empty() {
                return None;
            }
            continue;
        }
        match *word {
            "--" => options = false,
            "--message" | "--author" => {
                words.next()?;
                message |= *word == "--message";
            }
            value if value.starts_with("--message=") => message = true,
            value if value.starts_with("--author=") => {}
            // `-F -` takes the message from standard input, which the caller
            // proves carries literal data. A path reads that file instead,
            // and a commit message is not a read this proof covers.
            "--file" => {
                if *words.next()? != "-" {
                    return None;
                }
                message = true;
                standard_input = true;
            }
            "--file=-" => {
                message = true;
                standard_input = true;
            }
            value if value == "--gpg-sign" || value.starts_with("--gpg-sign=") => signs = true,
            "--quiet" | "--all" | "--signoff" | "--no-verify" | "--allow-empty"
            | "--no-gpg-sign" | "--reset-author" => {}
            "--amend" => amend = true,
            "--no-edit" => no_edit = true,
            value if value.starts_with("--") => return None,
            "-" => return None,
            cluster => {
                for (offset, flag) in cluster[1..].char_indices() {
                    match flag {
                        'q' | 'a' | 's' | 'n' => {}
                        // The rest of the cluster, or else the next word, is
                        // the message.
                        'm' => {
                            if cluster.len() == offset + 2 {
                                words.next()?;
                            }
                            message = true;
                            break;
                        }
                        // The rest of the cluster, or else the next word,
                        // names the file the message comes from.
                        'F' => {
                            let value = if cluster.len() == offset + 2 {
                                *words.next()?
                            } else {
                                &cluster[offset + 2..]
                            };
                            if value != "-" {
                                return None;
                            }
                            message = true;
                            standard_input = true;
                            break;
                        }
                        // The rest of the cluster names the key; Git never
                        // takes it from the next word.
                        'S' => {
                            signs = true;
                            break;
                        }
                        _ => return None,
                    }
                }
            }
        }
    }
    Some(CommitOptions {
        message,
        standard_input,
        amend,
        no_edit,
        signs,
    })
}

/// `branch -m NEW` or `branch -m OLD NEW`, options first. A rename moves the
/// ref with its reflog and refuses an existing target, so nothing becomes
/// unreachable. `-M`, `--force`, a copy and every other option are refused.
pub(super) fn branch_rename(rest: &[&str]) -> bool {
    let mut moved = false;
    let mut names = Vec::new();
    for word in rest {
        match *word {
            "-m" | "--move" if !moved && names.is_empty() => moved = true,
            "-q" | "--quiet" if names.is_empty() => {}
            name if super::super::worktree_add::valid_branch_name(name) => names.push(name),
            _ => return false,
        }
    }
    moved && matches!(names.len(), 1 | 2)
}

/// `branch NAME` or `branch NAME START`, options first. Creation writes one
/// new ref and nothing else: Git refuses a name that already exists without
/// `-f`, leaves `HEAD` and the working tree exactly as they are, and records
/// an upstream only in the same `branch.NAME.*` configuration that
/// `checkout -b NAME START` already writes for a remote-tracking start point.
/// `-f`, `-t`, `--set-upstream-to`, a delete, a copy and every other option
/// are refused, as is a start point that is not an ordinary reference name.
pub(super) fn branch_create(rest: &[&str]) -> bool {
    let mut names: Vec<&str> = Vec::new();
    for word in rest {
        match *word {
            "-q" | "--quiet" | "--no-track" if names.is_empty() => {}
            value if names.is_empty() => {
                if !super::super::worktree_add::valid_branch_name(value) {
                    return false;
                }
                names.push(value);
            }
            value if names.len() == 1 && super::start::reference(value) => names.push(value),
            _ => return false,
        }
    }
    !names.is_empty()
}

/// The two `git stash` spellings that only print are judged by the read
/// grammar, so a listing proved here and a listing proved as an ordinary
/// read can never drift apart.
pub(super) use crate::pretool::git_stash_reads::{list as stash_list, show as stash_show};

/// `stash apply` or `stash pop` with `-q`, `--index` and at most one entry
/// (`stash@{N}` or `N`). Git refuses to apply an entry over a modified file,
/// and `pop` keeps the entry when the apply conflicts.
pub(super) fn stash_restore(rest: &[&str]) -> bool {
    let mut entries = 0;
    rest.iter().all(|option| match *option {
        "-q" | "--quiet" | "--index" => true,
        entry if crate::pretool::git_stash_reads::entry_name(entry) => {
            entries += 1;
            entries == 1
        }
        _ => false,
    })
}

/// `(external diff disarmed, textconv disarmed)` for a `stash show`.
/// A summary never runs textconv; a patch does unless `--no-textconv` wins.
pub(super) fn show_diff_drivers_disarmed(segment: &CommandSegmentV1) -> Option<(bool, bool)> {
    if segment.arguments.first().map(String::as_str) != Some("stash")
        || segment.arguments.get(1).map(String::as_str) != Some("show")
    {
        return None;
    }
    let mut external = false;
    let mut textconv_flag = None;
    let mut patch = false;
    for flag in segment.arguments[2..]
        .iter()
        .map(String::as_str)
        .filter(|word| word.starts_with('-'))
    {
        match flag {
            "--no-ext-diff" => external = true,
            "--ext-diff" => external = false,
            "--no-textconv" => textconv_flag = Some(true),
            "--textconv" => textconv_flag = Some(false),
            "-p" | "-u" | "--patch" => patch = true,
            _ => {}
        }
    }
    Some((external, textconv_flag.unwrap_or(!patch)))
}

/// Whether the `git stash` at `index` starts no program its hooks do not
/// cover. Stash pages only under its own `pager.stash` setting, and the
/// command each form runs keeps its own pager key besides. `list` runs
/// `git log -g refs/stash`, held to the configuration proof of that log
/// read; `show` prints the entry's diff, held to the proof of a `git diff`
/// read; `apply` and `pop` merge the entry, which may run a configured merge
/// driver, and then run `git status`, held to the proof of that read.
pub(super) fn stash_free(
    effective: &GitConfig,
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let original = &model.segments[index];
    let stripped = super::super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    let stdout_piped = super::super::git_helper_context::stdout_piped(model, index);
    let free = |arguments: &[&str], pager: Option<&str>| {
        let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
        super::super::git_config::execution_free_paging(
            "git",
            &arguments,
            pager,
            context,
            deadline,
            execution_environment,
            stdout_piped,
        ) == Some(true)
    };
    let pager_off = |value: &String| {
        value.is_empty() || value == "cat" || super::super::git_remote_ops::pull::disabled(value)
    };
    let merge_driver = effective.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key.starts_with("merge.") && key.ends_with(".driver")
    });
    let stash_pages = stdout_piped
        || effective
            .get("pager.stash")
            .is_none_or(|values| values.iter().all(pager_off));
    // `stash show` prints the entry's diff, so it clears under the same
    // configuration proof a `git diff` read clears under, read with the
    // options the caller gave. `--no-ext-diff` and `--no-textconv` keep a
    // configured driver out of the read, and a summary form runs no textconv
    // program. It pages twice over: `pager.stash` decides whether the stash
    // command pages at all, and `show_stash` then asks for the diff pager, so
    // `pager.diff` starts a program of its own where `pager.stash` left the
    // choice open. Both keys are held to the proof.
    stash_pages
        && match segment.arguments.get(1).map(String::as_str) {
            Some("list") => free(&["log", "-g", "--first-parent", "refs/stash"], None),
            Some("show") => {
                let mut arguments = vec!["diff"];
                arguments.extend(
                    segment.arguments[2..]
                        .iter()
                        .map(String::as_str)
                        .filter(|word| word.starts_with('-')),
                );
                free(&arguments, None)
            }
            Some("apply" | "pop") => !merge_driver && free(&["status"], None),
            _ => true,
        }
}

/// Whether the configuration defines an alias named like a Git step's
/// subcommand. Git ignores an alias that shadows a builtin; the proof does
/// not rely on that.
pub(super) fn aliased(effective: &GitConfig, model: &CanonicalCommandV1) -> bool {
    model
        .segments
        .iter()
        .filter(|segment| segment.executable.as_deref() == Some("git"))
        .filter_map(|segment| segment.arguments.first())
        .any(|name| effective.contains_key(&format!("alias.{}", name.to_ascii_lowercase())))
}

/// The branch `git switch -c <name>`, `git switch --create=<name>` or
/// `git checkout -b <name>` creates at the checked-out commit. A start point
/// is not one of these forms.
pub(super) fn created_branch(original: &CommandSegmentV1) -> Option<&str> {
    let words: Vec<&str> = original.arguments.iter().map(String::as_str).collect();
    super::super::workspace_contained::created_branch_name(&words)
}

/// Whether a write other than a branch creation may change what a push would
/// send: any `checkout`, `switch` or `branch` form, and a `reset`, which moves
/// the checked-out branch to another commit.
pub(super) fn moves_head(original: &CommandSegmentV1) -> bool {
    original.arguments.first().is_none_or(|command| {
        matches!(command.as_str(), "checkout" | "switch" | "branch" | "reset")
    })
}

#[cfg(test)]
mod tests {
    use super::{commit_form, message_from_standard_input};

    /// The commit forms that take their message from standard input.
    ///
    /// The fixture tests around this proof accept the workspace sandbox as
    /// well as the write proof, so they stay quiet even if these forms stop
    /// being recognised. This reads the form directly, with no fixture and no
    /// fallback, so the recognition itself is what fails.
    #[test]
    fn a_message_read_from_standard_input_is_an_accepted_commit_form() {
        for rest in [
            &["-F", "-"][..],
            &["--file", "-"][..],
            &["--file=-"][..],
            &["-F-"][..],
            &["-qF", "-"][..],
            &["-q", "--allow-empty", "-F", "-"][..],
        ] {
            assert_eq!(commit_form(rest), Some(false), "{rest:?}");
        }
    }

    /// A message read from a file is a file read this proof does not cover,
    /// and a commit with no message at all is an editor session.
    #[test]
    fn a_message_read_from_a_path_is_not_an_accepted_commit_form() {
        for rest in [
            &["-F", "notes.txt"][..],
            &["--file", "notes.txt"][..],
            &["--file=notes.txt"][..],
            &["-Fnotes.txt"][..],
            &["--allow-empty"][..],
        ] {
            assert_eq!(commit_form(rest), None, "{rest:?}");
        }
    }

    /// Only a message read from standard input consumes a heredoc body in
    /// front of the commit. An amended message and a message on the command
    /// line are accepted commit forms that read nothing, so the projection
    /// that drops the body must not treat them as readers.
    #[test]
    fn only_a_message_from_standard_input_reads_the_body() {
        for rest in [
            &["-F", "-"][..],
            &["--file", "-"][..],
            &["--file=-"][..],
            &["-F-"][..],
            &["-qF", "-"][..],
        ] {
            assert!(message_from_standard_input(rest), "{rest:?}");
        }
        for rest in [
            &["-F", "notes.txt"][..],
            &["--file=notes.txt"][..],
            &["-Fnotes.txt"][..],
            &["-m", "subject"][..],
            &["--message=subject"][..],
            &["--amend", "--no-edit"][..],
        ] {
            assert!(!message_from_standard_input(rest), "{rest:?}");
        }
    }
}
