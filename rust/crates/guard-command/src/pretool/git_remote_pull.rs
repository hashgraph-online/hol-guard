//! `git pull` from `origin`: the proven `origin` refresh, then a fast-forward
//! of the current branch or a merge of the fetched branch into it. Both
//! rewrite the working tree, so the proof also needs everything a merge or
//! checkout could start to be absent: no rebase, signature check, fsmonitor,
//! moved worktree or filter driver other than the user's own Git LFS install,
//! an `origin` upstream when Git picks it, and no `post-merge` or
//! `post-index-change` hook. A pull that may merge also writes a merge commit,
//! so it additionally needs `merge_inert` and none of `MERGE_HOOKS`.

use super::config::GitConfig;
use super::Probe;

/// Every hook a merge or cherry-pick can run, including the commit it writes
/// and the automatic garbage collection after it.
pub(in crate::pretool) const MERGE_HOOKS: &[&str] = &[
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-merge",
    "post-rewrite",
    "post-index-change",
    "reference-transaction",
    "pre-auto-gc",
];
const FAST_FORWARD_HOOKS: &[&str] = &["post-merge", "post-index-change"];

/// The shape of a proven pull, or of a fast-forward merge of what a fetch
/// from `origin` brought in.
#[derive(Clone, Copy)]
pub(super) struct Pull {
    /// Git picks the upstream: no remote is named.
    pub(super) upstream: bool,
    /// Without `--ff-only`, Git may write a merge commit.
    pub(super) merge: bool,
    /// A pull fetches first; `git merge --ff-only origin/<branch>` reaches no
    /// remote, so it needs only the work tree half of the proof.
    pub(super) fetches: bool,
}

/// The shape of the arguments after `pull`: `--ff-only` or a merge, either
/// with no remote, where Git picks the upstream, or with `origin [branch]`.
/// `--rebase` and every other option keep the review.
pub(super) fn shaped(rest: &[String]) -> Option<Pull> {
    let mut fast_forward = false;
    let mut fetch = Vec::new();
    for argument in rest {
        match argument.as_str() {
            // `--ff`, `--no-ff` and `--ff-only` set one option; the last wins.
            "--ff-only" => fast_forward = true,
            "--ff" | "--no-ff" => fast_forward = false,
            "-q" | "--quiet" | "--no-edit" | "--no-rebase" => {}
            _ => fetch.push(argument.clone()),
        }
    }
    let merge = !fast_forward;
    if fetch.is_empty() {
        return Some(Pull {
            upstream: true,
            merge,
            fetches: true,
        });
    }
    // More than one branch would ask for an octopus merge.
    (fetch
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .count()
        <= 2
        && crate::command_compatibility::git_fetch_origin_shaped(&fetch))
    .then_some(Pull {
        upstream: false,
        merge,
        fetches: true,
    })
}

/// The arguments after `merge` for a fast-forward to the branch a fetch from
/// `origin` updated: `--ff-only`, at most quiet or `--no-edit`, and one
/// `origin/<branch>` or the upstream (`@{u}`, `@{upstream}`). `--ff` and
/// `--no-ff` are refused rather than ordered, and every other option, a local
/// branch, a tag or a commit id keeps the review.
pub(super) fn fast_forward_merge(rest: &[String]) -> Option<Pull> {
    let mut fast_forward = false;
    let mut target = None;
    for argument in rest {
        match argument.as_str() {
            "--ff-only" => fast_forward = true,
            "-q" | "--quiet" | "--no-edit" => {}
            "@{u}" | "@{upstream}" if target.is_none() => target = Some(true),
            value if target.is_none() && origin_branch(value) => target = Some(false),
            _ => return None,
        }
    }
    let upstream = target?;
    fast_forward.then_some(Pull {
        upstream,
        merge: false,
        fetches: false,
    })
}

/// `origin/<branch>` with a branch name `git check-ref-format` accepts and
/// no reflog, ancestry or range suffix.
fn origin_branch(word: &str) -> bool {
    let Some(branch) = word.strip_prefix("origin/") else {
        return false;
    };
    !branch.is_empty()
        && branch.len() <= 200
        && branch != "HEAD"
        && !branch.starts_with(['-', '.', '/'])
        && !branch.ends_with(['.', '/'])
        && !branch.ends_with(".lock")
        && !branch.contains("..")
        && !branch.contains("//")
        && !branch.contains("/.")
        && branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
}

/// Whether nothing the fast-forward or merge runs after the fetch can start
/// a program or write outside the checkout.
pub(super) fn pull_inert(
    effective: &GitConfig,
    repository: &GitConfig,
    pull: Pull,
    probe: &Probe,
) -> bool {
    let merge_driver = effective
        .keys()
        .any(|key| key.starts_with("merge.") && key.ends_with(".driver"));
    let routed = effective.iter().any(|(key, values)| {
        let enabled = values.iter().any(|value| !disabled(value));
        (key.starts_with("filter.") && (!standard_lfs(key, values) || repository.contains_key(key)))
            // The user's own `gpg.*` names a program that only a signature
            // check (`*.verifysignatures` below) or commit signing (refused by
            // `merge_inert`) starts. A repository's choice stays routed.
            || (key.starts_with("gpg.") && repository.contains_key(key))
            || key.starts_with("hook.")
            || key == "core.worktree"
            || (key == "core.fsmonitor" && enabled)
            || (key.ends_with(".verifysignatures") && enabled)
            // `git merge` reads the current branch's options before its own
            // arguments: `--verify-signatures` or `--autostash` from there
            // starts what the keys above and below refuse.
            || (key.starts_with("branch.") && key.ends_with(".mergeoptions"))
            // Reapplying an automatic stash is a merge that runs the
            // configured merge driver.
            || (key == "merge.autostash" && enabled && merge_driver)
            // `git merge` itself never rebases; only a pull reads these.
            || (pull.fetches
                && (key == "pull.rebase" || key.starts_with("branch.") && key.ends_with(".rebase"))
                && enabled)
            || (pull.upstream
                && key.starts_with("branch.")
                && key.ends_with(".remote")
                && values.iter().any(|value| value.trim() != "origin"))
    });
    let hooks = if pull.merge {
        MERGE_HOOKS
    } else {
        FAST_FORWARD_HOOKS
    };
    // A fast-forward or merge brings in a commit Guard has not read, and a
    // hooks directory below the repository may be a tracked one it adds a hook
    // to, however the user's configuration spells it. Only a directory that
    // resolves outside the checkout is not.
    // `git merge` and `git pull` honour `pager.<command>`, which may name a
    // program Git starts when the output is a terminal.
    let paged =
        pager_enabled(effective, "merge") || (pull.fetches && pager_enabled(effective, "pull"));
    !routed
        && !paged
        && !repository_lfs_program(repository)
        && !repository.contains_key("core.hookspath")
        && effective.get("core.hookspath").is_none_or(|values| {
            values
                .iter()
                .all(|value| value.starts_with('~') || std::path::Path::new(value).is_absolute())
                && probe.hooks_directory_outside_toplevel()
        })
        && (!pull.merge || merge_inert(effective, repository))
        && probe.hooks_inert(hooks.iter().copied())
}

/// Whether a merge, and the commit it may write, can start no program the
/// fast-forward checks above leave open: no merge driver, no strategy or
/// merge option chosen by configuration (a strategy name runs
/// `git-merge-<name>` from `PATH`), no commit signing or signature check, and
/// no editor the repository picks. Git opens an editor for a merge message
/// only on a terminal and without `--no-edit`; the user's own editor setting
/// is their choice, but a repository must not choose one for them.
pub(in crate::pretool) fn merge_inert(effective: &GitConfig, repository: &GitConfig) -> bool {
    !effective.iter().any(|(key, values)| {
        let enabled = values.iter().any(|value| !disabled(value));
        (key.starts_with("merge.") && (key.ends_with(".driver") || key.ends_with(".recursive")))
            // Merging a signed tag checks its signature with `gpg.program`.
            || (key.starts_with("gpg.") && repository.contains_key(key))
            || matches!(key.as_str(), "pull.twohead" | "pull.octopus")
            || (key.starts_with("branch.") && key.ends_with(".mergeoptions"))
            || (matches!(key.as_str(), "commit.gpgsign" | "merge.verifysignatures") && enabled)
    }) && !repository
        .keys()
        .any(|key| matches!(key.as_str(), "core.editor" | "sequence.editor"))
}

/// The filter `git lfs install` writes to the user's own configuration. A
/// repository cannot set it, and it names the installed `git-lfs` program.
pub(in crate::pretool) fn standard_lfs(key: &str, values: &[String]) -> bool {
    let expected = match key {
        "filter.lfs.clean" => "git-lfs clean -- %f",
        "filter.lfs.smudge" => "git-lfs smudge -- %f",
        "filter.lfs.process" => "git-lfs filter-process",
        "filter.lfs.required" => "true",
        _ => return false,
    };
    values.iter().all(|value| value.trim() == expected)
}

/// Git LFS also starts programs named by `lfs.extension.<name>.*`,
/// `lfs.customtransfer.<name>.path` and `lfs.standalonetransferagent`. A
/// repository can set those while leaving the user's filter alone.
pub(in crate::pretool) fn repository_lfs_program(repository: &GitConfig) -> bool {
    repository.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key.starts_with("lfs.")
            && (key.starts_with("lfs.extension.")
                || key.starts_with("lfs.customtransfer.")
                || key.ends_with(".standalonetransferagent"))
    })
}

/// Whether `pager.<command>` turns a pager on, or names a program, for that
/// Git command.
pub(in crate::pretool) fn pager_enabled(effective: &GitConfig, command: &str) -> bool {
    effective
        .get(&format!("pager.{command}"))
        .is_some_and(|values| values.iter().any(|value| !disabled(value)))
}

pub(in crate::pretool) fn disabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "false" | "no" | "off" | "0"
    )
}

#[cfg(test)]
mod tests {
    use super::fast_forward_merge;

    fn shape(words: &[&str]) -> Option<(bool, bool, bool)> {
        let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        fast_forward_merge(&words).map(|pull| (pull.upstream, pull.merge, pull.fetches))
    }

    #[test]
    fn a_fast_forward_merge_names_one_origin_branch_or_the_upstream() {
        for words in [
            &["--ff-only", "origin/main"][..],
            &["origin/main", "--ff-only"],
            &["-q", "--ff-only", "origin/feature/report-lane"],
            &["--quiet", "--no-edit", "--ff-only", "origin/release-1.2"],
        ] {
            assert_eq!(shape(words), Some((false, false, false)), "{words:?}");
        }
        for words in [&["--ff-only", "@{u}"][..], &["--ff-only", "@{upstream}"]] {
            assert_eq!(shape(words), Some((true, false, false)), "{words:?}");
        }
    }

    #[test]
    fn every_other_merge_keeps_the_review() {
        for words in [
            &["origin/main"][..],
            &["--ff", "origin/main"],
            &["--no-ff", "origin/main"],
            &["--ff-only", "--no-ff", "origin/main"],
            &["--ff-only", "--ff", "origin/main"],
            &["--ff-only"],
            &["--ff-only", "main"],
            &["--ff-only", "feat/x"],
            &["--ff-only", "upstream/main"],
            &["--ff-only", "FETCH_HEAD"],
            &["--ff-only", "36b51d1428"],
            &["--ff-only", "v1.2.0"],
            &["--ff-only", "origin/main", "origin/next"],
            &["--ff-only", "origin/main", "@{u}"],
            &["--ff-only", "origin/HEAD"],
            &["--ff-only", "origin/"],
            &["--ff-only", "origin/main~1"],
            &["--ff-only", "origin/main^"],
            &["--ff-only", "origin/main@{1}"],
            &["--ff-only", "origin/a..b"],
            &["--ff-only", "origin/-x"],
            &["--ff-only", "origin/x.lock"],
            &["--ff-only", "@{-1}"],
            &["--ff-only", "-s", "ours", "origin/main"],
            &["--ff-only", "--strategy=ours", "origin/main"],
            &["--ff-only", "-X", "theirs", "origin/main"],
            &["--ff-only", "--no-verify", "origin/main"],
            &["--ff-only", "-S", "origin/main"],
            &["--ff-only", "--gpg-sign", "origin/main"],
            &["--ff-only", "--verify-signatures", "origin/main"],
            &["--ff-only", "--squash", "origin/main"],
            &["--ff-only", "--autostash", "origin/main"],
            &["--ff-only", "--edit", "origin/main"],
            &["--ff-only", "-m", "x", "origin/main"],
            &["--ff-only", "--abort"],
            &["--ff-only", "--into-name", "x", "origin/main"],
        ] {
            assert_eq!(shape(words), None, "{words:?}");
        }
    }
}
