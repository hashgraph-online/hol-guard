//! `git merge` of one revision and `git cherry-pick` of named commits: how an
//! agent brings a branch up to date with `origin/main`, merges a fetched
//! `FETCH_HEAD` or carries a fix across. Both refuse to start when the
//! change would overwrite uncommitted work, and `ORIG_HEAD` and the reflog
//! still reach the commit they move from, so like the other local writes
//! they keep every change reachable. Beyond those writes they can start a
//! merge driver, a strategy named by configuration, a signature check or an
//! editor, so the configuration must name none of them (`merge_inert` in the
//! pull proof) and no hook either can run may be installed. A strategy
//! option, `--edit`, signing, `--abort`/`--continue` and every other option
//! keep the review.

use super::super::git_remote_config::GitConfig;

/// The hooks a merge or cherry-pick runs.
pub(super) const HOOKS: &[&str] = super::super::git_remote_ops::pull::MERGE_HOOKS;

/// `git merge [options] <revision>`, with one revision so Git picks no
/// octopus strategy.
pub(super) fn merge(rest: &[&str]) -> bool {
    let mut revisions = 0;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        match *word {
            "--no-edit" | "--ff" | "--no-ff" | "--ff-only" | "-q" | "--quiet" | "--stat" | "-n"
            | "--no-stat" | "--log" | "--no-log" | "--no-verify" | "--no-gpg-sign"
            | "--no-progress" => {}
            "-m" | "--message" => {
                if words.next().is_none() {
                    return false;
                }
            }
            value if value.starts_with("--message=") => {}
            value if revision(value) => revisions += 1,
            _ => return false,
        }
    }
    revisions == 1
}

/// `git cherry-pick [options] <commit>...`, committing each pick without
/// opening an editor.
pub(super) fn cherry_pick(rest: &[&str]) -> bool {
    let mut commits = 0;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        match *word {
            "-x"
            | "--ff"
            | "-s"
            | "--signoff"
            | "--allow-empty"
            | "--keep-redundant-commits"
            | "--no-gpg-sign"
            | "-n"
            | "--no-commit" => {}
            "-m" | "--mainline" => {
                if words
                    .next()
                    .is_none_or(|parent| parent.parse::<u8>().is_err())
                {
                    return false;
                }
            }
            value if revision(value) => commits += 1,
            _ => return false,
        }
    }
    commits > 0
}

/// A revision spelled as a branch, remote-tracking ref, `FETCH_HEAD`, commit
/// id or range: never an option.
fn revision(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 200
        && !word.starts_with('-')
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~' | '^'))
}

/// Whether the configuration lets a merge or cherry-pick start no program
/// beyond what the local write proof already refuses.
pub(super) fn inert(effective: &GitConfig, repository: &GitConfig) -> bool {
    super::super::git_remote_ops::pull::merge_inert(effective, repository)
}

#[cfg(test)]
mod tests {
    use super::{cherry_pick, merge};

    #[test]
    fn merge_takes_one_revision_and_no_program_choosing_option() {
        let allowed: &[&[&str]] = &[
            &["origin/main", "--no-edit"],
            &["FETCH_HEAD", "--no-edit"],
            &["origin/main"],
            &["--no-ff", "-m", "Merge main", "feat/x"],
            &["--ff-only", "-q", "36b51d1428"],
        ];
        for rest in allowed {
            assert!(merge(rest), "{rest:?}");
        }
        let reviewed: &[&[&str]] = &[
            &[],
            &["origin/main", "feat/x"],
            &["-s", "custom", "origin/main"],
            &["--strategy=custom", "origin/main"],
            &["-X", "theirs", "origin/main"],
            &["--edit", "origin/main"],
            &["-S", "origin/main"],
            &["--gpg-sign", "origin/main"],
            &["--abort"],
            &["--continue"],
            &["--squash", "origin/main"],
            &["--autostash", "origin/main"],
            &["-m"],
            &["origin/main@{1}"],
            &["$(id)"],
        ];
        for rest in reviewed {
            assert!(!merge(rest), "{rest:?}");
        }
    }

    #[test]
    fn cherry_pick_names_commits_without_an_editor_or_strategy() {
        let allowed: &[&[&str]] = &[
            &["36b51d1428"],
            &["36b51d1428", "300395d837", "64b5fdf03e"],
            &["-x", "main~2..main"],
            &["-m", "1", "36b51d1428"],
        ];
        for rest in allowed {
            assert!(cherry_pick(rest), "{rest:?}");
        }
        let reviewed: &[&[&str]] = &[
            &[],
            &["-e", "36b51d1428"],
            &["--edit", "36b51d1428"],
            &["--strategy=custom", "36b51d1428"],
            &["-X", "theirs", "36b51d1428"],
            &["--continue"],
            &["--abort"],
            &["--quit"],
            &["--skip"],
            &["-S", "36b51d1428"],
            &["-m", "x", "36b51d1428"],
            &["--stdin"],
        ];
        for rest in reviewed {
            assert!(!cherry_pick(rest), "{rest:?}");
        }
    }
}
