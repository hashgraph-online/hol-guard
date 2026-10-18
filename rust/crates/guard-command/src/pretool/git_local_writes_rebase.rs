//! `git rebase <upstream>` and `git rebase --continue`: starting a rebase
//! onto a ref the repository already holds, and continuing one after the
//! agent resolved a conflict. Both replay commits and leave `ORIG_HEAD` and
//! the reflog reaching the branch they moved from, so like the other local
//! writes they keep every change reachable, and a rebase refuses to start
//! over uncommitted work. Beyond those commits the sequencer can start an
//! `exec` line, a merge strategy or signing program, and the hooks a merge
//! runs: a resume's saved state must name none of them, a start must name no
//! option at all, and either way the configuration must pass the merge proof
//! and leave the merge backend in place. A start also checks the upstream
//! out, which can replace an ignored file the way a new branch at a start
//! point can, and `rebase.autoStash` and `rebase.updateRefs` turn a plain
//! start into the forms that stay reviewed as options, so the start carries
//! the branch proof's path check and refuses both settings. `--skip` and
//! `--abort` stay reviewed: both reset the working tree and discard the work
//! in progress.

use super::super::git_remote_config::GitConfig;
use super::super::git_session_probe::Probe;
use crate::CommandSegmentV1;
use std::fs;

/// The hooks the replayed commits run, plus `pre-rebase` and `post-checkout`.
pub(super) const HOOKS: &[&str] = &[
    "pre-rebase",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-merge",
    "post-rewrite",
    "post-checkout",
    "post-index-change",
    "reference-transaction",
    "pre-auto-gc",
];

/// State files the merge backend writes that name no program. A strategy,
/// its options, a signing key, an autostash or any file this list does not
/// know keeps the review.
const STATE: &[&str] = &[
    "allow_rerere_autoupdate",
    "amend",
    "author-script",
    "cdate_is_adate",
    "current-fixups",
    "done",
    "drop_redundant_commits",
    "dropped",
    "end",
    "git-rebase-todo",
    "git-rebase-todo.backup",
    "head-name",
    "ignore_date",
    "interactive",
    "keep_redundant_commits",
    "message",
    "message-fixup",
    "message-squash",
    "msgnum",
    "no-reschedule-failed-exec",
    "onto",
    "orig-head",
    "patch",
    "quiet",
    "reschedule-failed-exec",
    "rewritten-list",
    "rewritten-pending",
    "signoff",
    "squash-onto",
    "stopped-sha",
    "update-refs",
    "verbose",
];

/// Todo commands that only replay, reword, fold or drop a commit, stop, or
/// name a ref. `exec` runs a shell command; `merge` may name a strategy and
/// `reset` checks out over the working tree.
const STEPS: &[&str] = &[
    "pick",
    "p",
    "reword",
    "r",
    "edit",
    "e",
    "squash",
    "s",
    "fixup",
    "f",
    "drop",
    "d",
    "break",
    "b",
    "label",
    "l",
    "update-ref",
    "u",
    "noop",
];

/// `git rebase --continue`, the form that carries a stopped rebase on.
pub(super) fn resume(rest: &[&str]) -> bool {
    matches!(rest, ["--continue"])
}

/// `git rebase <upstream>`, the form that starts one. Every option a rebase
/// takes either names a program (`-x`, `-s`, `-X`, `-S`, and `-i` with the
/// editor it opens), moves the replay somewhere the operand does not say
/// (`--onto`, `--root`) or writes over the working tree (`--autostash`), so
/// only `-q` stands beside the upstream. A second operand would check that
/// branch out first, which this form does not prove.
pub(super) fn start(rest: &[&str]) -> bool {
    upstream(rest).is_some()
}

/// The ref a start replays onto, or `None` when the words are not a start.
/// A pseudo-ref is not one: the rebase writes `ORIG_HEAD` as it begins, so
/// replaying onto it would leave the commit it named with no ref of its own,
/// and `HEAD` and the other operation heads are written the same way.
fn upstream<'words>(rest: &[&'words str]) -> Option<&'words str> {
    let mut upstream = None;
    for word in rest {
        match *word {
            "-q" | "--quiet" => {}
            value if super::start::reference(value) && durable(value) => {
                if upstream.replace(value).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    upstream
}

/// Whether the name is a ref of the repository's own rather than one of the
/// heads Git's operations write.
fn durable(value: &str) -> bool {
    let name = value.rsplit('/').next().unwrap_or(value);
    !(name == "HEAD"
        || (name.ends_with("_HEAD")
            && name
                .chars()
                .all(|letter| letter.is_ascii_uppercase() || letter == '_')))
}

/// Whether the repository holds what the rebase form in `original` needs: a
/// resume needs a merge-backend rebase in progress carrying only the state
/// files above, and a start needs no rebase in progress at all, so no saved
/// todo list or strategy reaches it.
pub(super) fn proven(probe: &Probe, original: &CommandSegmentV1, effective: &GitConfig) -> bool {
    let stripped = super::super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    let Some((&"rebase", rest)) = words.split_first() else {
        return false;
    };
    if resume(rest) {
        return resumable(probe);
    }
    let Some(upstream) = upstream(rest) else {
        return false;
    };
    idle(probe)
        && merge_backend(effective)
        && !worktree_configured(effective)
        && super::start::replaces_nothing(probe, upstream)
}

/// Whether the configuration turns a plain start into one of the forms that
/// stay reviewed as options. `rebase.autoStash` stashes the working tree and
/// reapplies it over the rebased commits, which is what `--autostash` does,
/// and `rebase.updateRefs` moves the other branches pointing into the
/// replayed range, which the operand does not name.
fn worktree_configured(effective: &GitConfig) -> bool {
    ["rebase.autostash", "rebase.updaterefs"].iter().any(|key| {
        effective.get(*key).is_some_and(|values| {
            values
                .iter()
                .any(|value| !super::super::git_remote_ops::pull::disabled(value))
        })
    })
}

/// Whether no rebase is in progress.
fn idle(probe: &Probe) -> bool {
    let Some((merge, apply)) = state_paths(probe) else {
        return false;
    };
    fs::symlink_metadata(merge).is_err() && fs::symlink_metadata(apply).is_err()
}

/// `rebase.backend = apply` replays with `git am`, which runs the
/// `applypatch-msg`, `pre-applypatch` and `post-applypatch` hooks no proof
/// here holds, so only the merge backend stays quiet.
fn merge_backend(effective: &GitConfig) -> bool {
    effective.get("rebase.backend").is_none_or(|values| {
        values
            .iter()
            .all(|value| value.trim().eq_ignore_ascii_case("merge"))
    })
}

/// The `rebase-merge` and `rebase-apply` directories of this repository.
fn state_paths(probe: &Probe) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let path =
        |name: &str| probe.text(&["rev-parse", "--path-format=absolute", "--git-path", name]);
    let (merge, apply) = (path("rebase-merge")?, path("rebase-apply")?);
    let (merge, apply) = (
        std::path::PathBuf::from(merge),
        std::path::PathBuf::from(apply),
    );
    merge.is_absolute().then_some((merge, apply))
}

/// Whether the rebase in progress uses the merge backend with only the state
/// files and todo steps above. The apply backend runs `git am` and its
/// hooks, so a `rebase-apply` directory keeps the review.
pub(super) fn resumable(probe: &Probe) -> bool {
    let Some((merge, apply)) = state_paths(probe) else {
        return false;
    };
    if fs::symlink_metadata(apply).is_ok() {
        return false;
    }
    let Ok(mut entries) = fs::read_dir(&merge) else {
        return false;
    };
    let known = entries.all(|entry| {
        entry.ok().is_some_and(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| STATE.contains(&name))
        })
    });
    known
        && fs::read_to_string(merge.join("git-rebase-todo"))
            .is_ok_and(|todo| todo.lines().all(step))
        && fs::read_to_string(merge.join("author-script")).map_or_else(
            |error| error.kind() == std::io::ErrorKind::NotFound,
            |text| author_script(&text),
        )
}

/// An `author-script` of single-quoted author assignments only. Older Git
/// sourced this file as shell, so anything beyond a quoted name, email or
/// date keeps the review.
fn author_script(text: &str) -> bool {
    text.lines().filter(|line| !line.is_empty()).all(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        matches!(
            key,
            "GIT_AUTHOR_NAME" | "GIT_AUTHOR_EMAIL" | "GIT_AUTHOR_DATE"
        ) && value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .is_some_and(|inner| inner.replace("'\\''", "").find('\'').is_none())
    })
}

/// A todo line that is blank, a comment or one of the steps above.
fn step(line: &str) -> bool {
    let line = line.trim();
    line.is_empty()
        || line.starts_with('#')
        || line
            .split_whitespace()
            .next()
            .is_some_and(|command| STEPS.contains(&command))
}

#[cfg(test)]
mod tests {
    use super::{author_script, durable, merge_backend, resume, start, step, worktree_configured};

    #[test]
    fn only_continue_with_replay_steps_is_a_resumable_form() {
        assert!(resume(&["--continue"]));
        let reviewed: &[&[&str]] = &[
            &["--skip"],
            &["--abort"],
            &["--quit"],
            &["--edit-todo"],
            &["--continue", "-x", "id"],
            &["origin/main"],
            &[],
        ];
        for rest in reviewed {
            assert!(!resume(rest), "{rest:?}");
        }
        for line in [
            "pick 6953422 c",
            "  fixup -C 6953422 c",
            "reword 6953422 c",
            "update-ref refs/heads/topic",
            "# exec id",
            "",
        ] {
            assert!(step(line), "{line}");
        }
        assert!(author_script(
            "GIT_AUTHOR_NAME='A O'\\''B'\nGIT_AUTHOR_EMAIL='a@b.c'\nGIT_AUTHOR_DATE='@1 +0000'\n"
        ));
        for script in [
            "GIT_AUTHOR_NAME='a'; id\n",
            "GIT_AUTHOR_NAME='a'$(id)''\n",
            "GIT_AUTHOR_NAME=\"$(id)\"\n",
            "GIT_AUTHOR_NAME='a'\nid\n",
            "PATH='/tmp'\n",
            "GIT_AUTHOR_NAME='a' id\n",
        ] {
            assert!(!author_script(script), "{script}");
        }
        for line in [
            "exec id",
            "x id",
            "merge -C 6953422 topic",
            "m topic",
            "reset onto",
            "t onto",
            "execute id",
        ] {
            assert!(!step(line), "{line}");
        }
    }

    #[test]
    fn a_start_names_one_upstream_and_no_option_that_runs_a_program() {
        let allowed: &[&[&str]] = &[
            &["main"],
            &["origin/main"],
            &["-q", "origin/main"],
            &["upstream/release-1.2", "--quiet"],
        ];
        for rest in allowed {
            assert!(start(rest), "{rest:?}");
        }
        let reviewed: &[&[&str]] = &[
            &[],
            &["-q"],
            &["main", "feat/x"],
            &["-i", "main"],
            &["--interactive", "main"],
            &["-x", "id", "main"],
            &["--exec=id", "main"],
            &["--onto", "main", "topic"],
            &["--root"],
            &["-s", "ort", "main"],
            &["-X", "theirs", "main"],
            &["-S", "main"],
            &["--autostash", "main"],
            // The rebase writes these itself, so replaying onto one can drop
            // the only name the commit it pointed at still had.
            &["ORIG_HEAD"],
            &["HEAD"],
            &["FETCH_HEAD"],
            &["CHERRY_PICK_HEAD"],
            &["--continue"],
            &["--abort"],
            &["main@{1}"],
            &["$(id)"],
        ];
        for rest in reviewed {
            assert!(!start(rest), "{rest:?}");
        }
    }

    #[test]
    fn only_the_merge_backend_replays_without_the_apply_hooks() {
        let backend = |value: &str| {
            std::collections::BTreeMap::from([(
                "rebase.backend".to_owned(),
                vec![value.to_owned()],
            )])
        };
        assert!(merge_backend(&std::collections::BTreeMap::new()));
        assert!(merge_backend(&backend("merge")));
        assert!(merge_backend(&backend(" Merge ")));
        assert!(!merge_backend(&backend("apply")));
        assert!(!merge_backend(&backend("am")));
    }

    #[test]
    fn configured_autostash_or_ref_updates_keep_a_start_reviewed() {
        let configured = |key: &str, value: &str| {
            std::collections::BTreeMap::from([(key.to_owned(), vec![value.to_owned()])])
        };
        assert!(!worktree_configured(&std::collections::BTreeMap::new()));
        for key in ["rebase.autostash", "rebase.updaterefs"] {
            for value in ["true", "yes", "on", "1", ""] {
                assert!(
                    worktree_configured(&configured(key, value)),
                    "{key} {value}"
                );
            }
            for value in ["false", "no", "off", "0"] {
                assert!(
                    !worktree_configured(&configured(key, value)),
                    "{key} {value}"
                );
            }
        }
    }

    #[test]
    fn an_operation_head_is_not_an_upstream_a_start_may_name() {
        for value in ["main", "origin/main", "release/HEADS", "head", "my_head"] {
            assert!(durable(value), "{value}");
        }
        for value in [
            "HEAD",
            "ORIG_HEAD",
            "FETCH_HEAD",
            "MERGE_HEAD",
            "REBASE_HEAD",
            "refs/ORIG_HEAD",
        ] {
            assert!(!durable(value), "{value}");
        }
    }
}
