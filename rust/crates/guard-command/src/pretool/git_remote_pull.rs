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
#[derive(Clone, Copy, Debug)]
pub(super) struct Pull {
    /// Git picks the upstream: no remote is named.
    pub(super) upstream: bool,
    /// Without `--ff-only`, Git may write a merge commit.
    pub(super) merge: bool,
    /// A pull fetches first; `git merge --ff-only origin/<branch>` reaches no
    /// remote, so it needs only the work tree half of the proof.
    pub(super) fetches: bool,
}

/// What the proof must cover for one remote segment: the pull or merge shape
/// when the segment is one, and whether the refresh reaches every remote the
/// repository configures rather than the `origin` it names.
#[derive(Clone, Copy)]
pub(super) struct Operation {
    pub(super) upstream: Option<Pull>,
    pub(super) every_remote: bool,
}

impl Operation {
    /// A pull or merge. Both name what they reach, so neither walks the
    /// repository's other remotes.
    pub(super) fn upstream(shape: Pull) -> Self {
        Self {
            upstream: Some(shape),
            every_remote: false,
        }
    }
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

/// Whether the configuration alone, before any probe of the checkout, names
/// something the fast-forward or merge would start.
fn configuration_routed(effective: &GitConfig, repository: &GitConfig, pull: Pull) -> bool {
    let merge_driver = effective
        .keys()
        .any(|key| key.starts_with("merge.") && key.ends_with(".driver"));
    effective.iter().any(|(key, values)| {
        let enabled = values.iter().any(|value| !disabled(value));
        (key.starts_with("filter.") && (!standard_lfs(key, values) || repository.contains_key(key)))
            // `gpg.*` names a program that a signature check
            // (`*.verifysignatures` below), commit signing, or the merge
            // message starts: Git builds that message before it decides to
            // fast-forward, and verifies a signed tag there with
            // `gpg.program`. A repository's own copy of the key is refused
            // unless it only restates what the user already set.
            || (key.starts_with("gpg.")
                && repository.contains_key(key)
                && !repository_restates_user(effective, repository, key))
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
    })
}

/// Whether the user's own configuration already decides this key, so the
/// repository's copy changes nothing Git would do. `git config --show-scope
/// --list` reports every scope's entry in Git's own order and the last one
/// wins, so the repository changes nothing when the entry an outer scope
/// already set carries the value Git ends up using. The repository's scopes
/// are read after the user's, so its entries stand at the end of the
/// effective list; a trailing run that is not the repository's own is a
/// shape this reader does not decide.
fn repository_restates_user(effective: &GitConfig, repository: &GitConfig, key: &str) -> bool {
    let Some(local) = repository.get(key) else {
        return false;
    };
    let Some(all) = effective.get(key) else {
        return false;
    };
    let Some((outer, tail)) = all
        .len()
        .checked_sub(local.len())
        .map(|at| all.split_at(at))
    else {
        return false;
    };
    tail == local.as_slice() && outer.last().is_some() && outer.last() == all.last()
}

/// Whether nothing the fast-forward or merge runs after the fetch can start
/// a program or write outside the checkout.
pub(super) fn pull_inert(
    effective: &GitConfig,
    repository: &GitConfig,
    pull: Pull,
    probe: &Probe,
) -> bool {
    let routed = configuration_routed(effective, repository, pull);
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
    use super::{configuration_routed, fast_forward_merge, merge_inert, GitConfig, Pull};

    fn config(entries: &[(&str, &str)]) -> GitConfig {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), vec![(*value).to_owned()]))
            .collect()
    }

    /// The signing settings an identity hook writes into every checkout it
    /// touches, beside the user's own global copy of them. `--show-scope`
    /// reports both, so the effective entry for each key holds two values.
    fn signed() -> (GitConfig, GitConfig) {
        let repository = config(&[
            ("gpg.format", "openpgp"),
            ("gpg.program", "/home/dev/.git-hooks/sign-commit.sh"),
            ("commit.gpgsign", "true"),
            ("core.pager", "cat"),
            ("pager.log", "false"),
            ("pull.rebase", "false"),
        ]);
        let effective = repository
            .iter()
            .map(|(key, values)| (key.clone(), [values.clone(), values.clone()].concat()))
            .collect();
        (effective, repository)
    }

    #[test]
    fn a_repository_signing_program_leaves_a_fast_forward_alone() {
        let (effective, repository) = signed();
        for pull in [
            Pull {
                upstream: false,
                merge: false,
                fetches: true,
            },
            Pull {
                upstream: true,
                merge: false,
                fetches: true,
            },
            Pull {
                upstream: false,
                merge: false,
                fetches: false,
            },
        ] {
            assert!(
                !configuration_routed(&effective, &repository, pull),
                "{pull:?}"
            );
        }
    }

    #[test]
    fn a_repository_signing_program_still_refuses_a_merge() {
        let (effective, repository) = signed();
        let pull = Pull {
            upstream: false,
            merge: true,
            fetches: true,
        };
        // The commit a merge writes is signed with it, which `merge_inert`
        // refuses whichever scope holds the program.
        assert!(!configuration_routed(&effective, &repository, pull));
        assert!(!merge_inert(&effective, &repository));
    }

    /// Git builds the merge message before it decides to fast-forward, and
    /// verifies a signed tag there with `gpg.program`. A repository that names
    /// its own program keeps the review even for a fast-forward.
    #[test]
    fn a_repository_program_the_user_never_set_routes_a_fast_forward() {
        let (mut effective, mut repository) = signed();
        let planted = vec!["/src/.git/hooks/sign.sh".to_owned()];
        effective.insert("gpg.program".to_owned(), planted.clone());
        repository.insert("gpg.program".to_owned(), planted);
        let pull = Pull {
            upstream: false,
            merge: false,
            fetches: true,
        };
        assert!(configuration_routed(&effective, &repository, pull));
    }

    /// A repository that overrides the user's own program with a different
    /// one keeps the review too: the effective entries disagree.
    #[test]
    fn a_repository_program_that_differs_routes_a_fast_forward() {
        let (mut effective, mut repository) = signed();
        let planted = "/src/.git/hooks/sign.sh".to_owned();
        effective
            .get_mut("gpg.program")
            .expect("signed")
            .push(planted.clone());
        repository.insert("gpg.program".to_owned(), vec![planted]);
        let pull = Pull {
            upstream: false,
            merge: false,
            fetches: true,
        };
        assert!(configuration_routed(&effective, &repository, pull));
    }

    /// The user's global configuration sets `gpg.program` once for every
    /// checkout and again, to the signing wrapper, behind the conditional
    /// include that covers this one. Git uses the last entry, which the
    /// repository's copy restates, so the fast-forward stays where it was.
    #[test]
    fn an_outer_scope_the_include_overrides_leaves_a_fast_forward_alone() {
        let (mut effective, repository) = signed();
        effective
            .get_mut("gpg.program")
            .expect("signed")
            .insert(0, "gpg".to_owned());
        let pull = Pull {
            upstream: false,
            merge: false,
            fetches: true,
        };
        assert!(!configuration_routed(&effective, &repository, pull));
    }

    /// `git -c gpg.program=...` is read after the repository's own scopes, so
    /// the entries at the end of the effective list are not the repository's
    /// and the reader does not decide the key.
    #[test]
    fn a_scope_after_the_repository_routes_a_fast_forward() {
        let (mut effective, repository) = signed();
        effective
            .get_mut("gpg.program")
            .expect("signed")
            .push("/src/.git/hooks/sign.sh".to_owned());
        let pull = Pull {
            upstream: false,
            merge: false,
            fetches: true,
        };
        assert!(configuration_routed(&effective, &repository, pull));
    }

    #[test]
    fn the_users_own_signing_program_routes_neither() {
        let (effective, _) = signed();
        let repository = GitConfig::new();
        for merge in [false, true] {
            let pull = Pull {
                upstream: false,
                merge,
                fetches: true,
            };
            // `commit.gpgsign` still refuses the commit a merge writes.
            assert!(
                !configuration_routed(&effective, &repository, pull),
                "{merge}"
            );
        }
        assert!(!merge_inert(&effective, &repository));
    }

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
