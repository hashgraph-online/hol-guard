//! `git rebase --continue` after the agent resolved a conflict. The rebase
//! already chose its commits; continuing commits the resolved index and
//! replays the rest of the todo list, and `ORIG_HEAD` and the reflog still
//! reach the branch it started from, so like the other local writes it keeps
//! every change reachable. Beyond those commits the sequencer can start an
//! `exec` line, a merge strategy or signing program saved in its state, and
//! the hooks a merge runs, so the state must name none of them and the
//! configuration must pass the merge proof. `--skip` and `--abort` stay
//! reviewed: both reset the working tree and discard the work in progress.

use super::super::git_session_probe::Probe;
use std::fs;
use std::path::Path;

/// The hooks the replayed commits run, plus `post-checkout`.
pub(super) const HOOKS: &[&str] = &[
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

/// `git rebase --continue`, the only rebase form proven here.
pub(super) fn resume(rest: &[&str]) -> bool {
    matches!(rest, ["--continue"])
}

/// Whether the rebase in progress uses the merge backend with only the state
/// files and todo steps above. The apply backend runs `git am` and its
/// hooks, so a `rebase-apply` directory keeps the review.
pub(super) fn resumable(probe: &Probe) -> bool {
    let path =
        |name: &str| probe.text(&["rev-parse", "--path-format=absolute", "--git-path", name]);
    let (Some(merge), Some(apply)) = (path("rebase-merge"), path("rebase-apply")) else {
        return false;
    };
    let (merge, apply) = (Path::new(&merge), Path::new(&apply));
    if !merge.is_absolute() || fs::symlink_metadata(apply).is_ok() {
        return false;
    }
    let Ok(mut entries) = fs::read_dir(merge) else {
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
    use super::{author_script, resume, step};

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
}
