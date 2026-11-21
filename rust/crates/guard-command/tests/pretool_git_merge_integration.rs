#![cfg(unix)]

//! Bringing a checkout up to date: `git merge` of one revision, `git
//! cherry-pick` of named commits, `git rebase` onto a local ref and `git pull
//! origin <branch>` that may write a merge commit, in a sibling repository
//! behind `git -C` or after a `sleep`. They stay quiet only while no hook, merge driver, configured
//! strategy, signing step or repository-chosen editor can run; every option
//! that picks a program or discards work keeps the review.

use crate::pretool_git_session_ops::{executable_hook, git, session, Session};
use std::path::PathBuf;

const LOCAL_WRITE: &str = "native_exact_safe_git_local_write";
const REFRESH: &str = "native_exact_safe_git_origin_refresh";

/// The session plus `org/service-api`, a sibling repository of the cwd.
fn sibling(label: &str) -> (Session, PathBuf) {
    let session = session(label);
    let service = session.org.join("service-api");
    std::fs::create_dir_all(&service).unwrap();
    let setup: [&[&str]; 3] = [
        &["init", "--quiet", "-b", "main"],
        &["config", "user.name", "Guard Fixture"],
        &["config", "user.email", "guard-fixture@example.invalid"],
    ];
    for arguments in setup {
        git(&session.home, &service, arguments);
    }
    std::fs::write(service.join("README.md"), "fixture\n").unwrap();
    git(&session.home, &service, &["add", "README.md"]);
    git(
        &session.home,
        &service,
        &["commit", "--quiet", "-m", "fixture"],
    );
    // A rebase start proves its upstream resolves to a commit, so the sibling
    // carries the remote-tracking ref an ordinary checkout holds.
    git(
        &session.home,
        &service,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    (session, service)
}

fn reason(session: &Session, command: &str, cwd: &std::path::Path) -> Option<String> {
    let result = session.evaluate_at(command, cwd);
    (result.minimum_action == "allow").then_some(result.reason_code)
}

fn assert_allowed(session: &Session, command: &str, cwd: &std::path::Path, expected: &str) {
    let result = session.evaluate_at(command, cwd);
    assert_eq!(
        (result.minimum_action == "allow").then_some(result.reason_code.as_str()),
        Some(expected),
        "{command}: {} {}",
        result.reason_code,
        result.reason
    );
}

fn assert_reviewed(session: &Session, command: &str, cwd: &std::path::Path) {
    assert_eq!(reason(session, command, cwd), None, "{command}");
}

fn configured(session: &Session, repository: &std::path::Path, key: &str, value: Option<&str>) {
    match value {
        Some(value) => git(&session.home, repository, &["config", key, value]),
        None => git(&session.home, repository, &["config", "--unset-all", key]),
    }
}

#[test]
fn sibling_merge_and_cherry_pick_behind_git_c_are_local_writes() {
    let (session, service) = sibling("merge-sibling");
    let cwd = session.primary.clone();
    let sib = service.display();
    for command in [
        format!("git -C {sib} merge origin/main --no-edit 2>&1 | tail -3"),
        format!("git -C {sib} merge FETCH_HEAD --no-edit"),
        format!("git -C {sib} merge origin/main"),
        format!("sleep 120; git -C {sib} merge origin/main --no-edit"),
        format!("sleep 300; git -C {sib} merge origin/main --no-edit 2>&1 | tail -4"),
        format!("git -C {sib} cherry-pick 36b51d1428 300395d837 64b5fdf03e 2>&1 | tail -4"),
        format!("sleep 420; git -C {sib} cherry-pick 36b51d1428 2>&1 | tail -2"),
        format!("git -C {sib} cherry-pick -x 36b51d1428"),
        format!("git -C {sib} rebase origin/main"),
    ] {
        assert_allowed(&session, &command, &cwd, LOCAL_WRITE);
    }
    for command in [
        // A strategy runs `git-merge-<name>` from PATH; an option picks one.
        format!("git -C {sib} merge -s custom origin/main"),
        format!("git -C {sib} merge -X theirs origin/main"),
        format!("git -C {sib} merge origin/main feat/x"),
        format!("git -C {sib} merge --edit origin/main"),
        format!("git -C {sib} merge -S origin/main"),
        format!("git -C {sib} merge --abort"),
        format!("git -C {sib} cherry-pick -e 36b51d1428"),
        format!("git -C {sib} cherry-pick --continue"),
        format!("git -C {sib} cherry-pick --strategy=custom 36b51d1428"),
        format!("git -C {sib} -c merge.ff=false merge origin/main"),
        format!("GIT_EDITOR=/tmp/editor git -C {sib} merge origin/main"),
        // Neighbours that discard work, and rebase forms that run a program.
        format!("git -C {sib} reset --hard origin/main"),
        format!("git -C {sib} rebase --abort"),
        format!("git -C {sib} rebase -x id origin/main"),
        format!("git -C {sib} rebase --onto main origin/main topic"),
        format!("git -C {sib} checkout -- README.md"),
        // Steps other than Git run from the shell's directory.
        format!("git -C {sib} merge origin/main --no-edit && rm -rf build"),
        format!("sleep 120; git -C {sib} merge origin/main; bash run.sh"),
    ] {
        assert_reviewed(&session, &command, &cwd);
    }
}

#[test]
fn merge_stays_reviewed_when_configuration_or_hooks_can_start_a_program() {
    let (session, service) = sibling("merge-config");
    let cwd = session.primary.clone();
    let sib = service.display();
    let merge = format!("git -C {sib} merge origin/main --no-edit");
    let pick = format!("git -C {sib} cherry-pick 36b51d1428");
    assert_allowed(&session, &merge, &cwd, LOCAL_WRITE);
    for (key, value) in [
        ("merge.custom.driver", "sh -c id %O %A %B"),
        ("pull.twohead", "custom"),
        ("pull.octopus", "custom"),
        ("branch.main.mergeoptions", "-s custom"),
        ("merge.verifySignatures", "true"),
        ("gpg.program", "/tmp/gpg"),
        ("commit.gpgsign", "true"),
        ("core.editor", "/tmp/editor"),
        ("sequence.editor", "/tmp/editor"),
        ("filter.fixture.smudge", "id"),
        ("core.fsmonitor", "/tmp/monitor"),
        ("hook.post-merge.command", "id"),
    ] {
        configured(&session, &service, key, Some(value));
        assert_reviewed(&session, &merge, &cwd);
        assert_reviewed(&session, &pick, &cwd);
        configured(&session, &service, key, None);
    }
    assert_allowed(&session, &pick, &cwd, LOCAL_WRITE);
    for hook in [
        "pre-merge-commit",
        "prepare-commit-msg",
        "commit-msg",
        "post-commit",
        "post-merge",
        "post-rewrite",
        "reference-transaction",
    ] {
        let path = service.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_reviewed(&session, &merge, &cwd);
        assert_reviewed(&session, &pick, &cwd);
        std::fs::remove_file(path).unwrap();
    }
}

/// A start replays onto the upstream and checks it out first, so the hooks
/// that run and the configuration that moves more than the branch keep it
/// under review.
#[test]
fn a_rebase_start_stays_reviewed_when_configuration_or_hooks_change_the_replay() {
    let (session, service) = sibling("rebase-config");
    let cwd = session.primary.clone();
    let sib = service.display();
    let rebase = format!("git -C {sib} rebase origin/main");
    assert_allowed(&session, &rebase, &cwd, LOCAL_WRITE);
    for (key, value) in [
        ("rebase.backend", "apply"),
        ("rebase.autoStash", "true"),
        ("rebase.updateRefs", "true"),
    ] {
        configured(&session, &service, key, Some(value));
        assert_reviewed(&session, &rebase, &cwd);
        configured(&session, &service, key, None);
    }
    assert_allowed(&session, &rebase, &cwd, LOCAL_WRITE);
    for hook in ["pre-rebase", "post-checkout"] {
        let path = service.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_reviewed(&session, &rebase, &cwd);
        std::fs::remove_file(path).unwrap();
    }
    // The rebase writes `ORIG_HEAD` as it starts, so replaying onto it could
    // leave the commit it named with no ref of its own.
    assert_reviewed(&session, &format!("git -C {sib} rebase ORIG_HEAD"), &cwd);
}

#[test]
fn merge_pull_from_origin_is_a_proven_refresh_without_commit_programs() {
    let session = session("merge-pull");
    let cwd = session.org.clone();
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull origin main --no-edit");
    let fast_forward = format!("git -C {primary} pull --ff-only origin main");
    let last_no_ff = format!("git -C {primary} pull --ff-only --no-ff origin main");
    let last_ff_only = format!("git -C {primary} pull --no-ff --ff-only origin main");
    for command in [
        pull.clone(),
        format!("git -C {primary} pull origin main --no-edit 2>&1 | tail -3"),
        format!("sleep 300; git -C {primary} pull origin main --no-edit"),
        format!("git -C {primary} pull --no-rebase origin main"),
    ] {
        assert_allowed(&session, &command, &cwd, REFRESH);
    }
    for command in [
        format!("git -C {primary} pull --rebase origin main"),
        format!("git -C {primary} pull -s custom origin main"),
        format!("git -C {primary} pull -X theirs origin main"),
        format!("git -C {primary} pull --edit origin main"),
        format!("git -C {primary} pull origin main feat/x"),
        format!("git -C {primary} pull evil main --no-edit"),
    ] {
        assert_reviewed(&session, &command, &cwd);
    }
    for (key, value) in [
        ("merge.custom.driver", "sh -c id %O %A %B"),
        ("pull.twohead", "custom"),
        ("branch.main.mergeoptions", "-s custom"),
        ("commit.gpgsign", "true"),
        ("core.editor", "/tmp/editor"),
    ] {
        session.config(&[key, value]);
        assert_reviewed(&session, &pull, &cwd);
        session.config(&["--unset-all", key]);
    }
    // A fast-forward writes no commit, so a commit hook keeps only the merge
    // pull reviewed.
    for hook in ["pre-merge-commit", "prepare-commit-msg", "commit-msg"] {
        let path = session.primary.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_reviewed(&session, &pull, &cwd);
        assert_allowed(&session, &fast_forward, &cwd, REFRESH);
        assert_allowed(&session, &last_ff_only, &cwd, REFRESH);
        assert_reviewed(&session, &last_no_ff, &cwd);
        std::fs::remove_file(path).unwrap();
    }
    assert_allowed(&session, &pull, &cwd, REFRESH);
}

/// The user configuration a Git LFS install, a GPG setup and a shared hooks
/// directory leave behind.
const USER_CONFIG: &str = "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\
    \tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\
    \trequired = true\n[gpg]\n\tprogram = gpg\n[core]\n\thooksPath = ~/.config/git/hooks\n";

#[test]
fn pulls_stay_refreshes_under_the_users_own_gpg_program() {
    let session = session("merge-pull-user-gpg");
    let cwd = session.org.clone();
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull origin main --no-edit");
    let fast_forward = format!("git -C {primary} pull --ff-only origin main");
    let global = session.home.join(".gitconfig");
    std::fs::create_dir_all(session.home.join(".config/git/hooks")).unwrap();
    std::fs::write(&global, USER_CONFIG).unwrap();
    // The program runs only when Git signs or checks a signature.
    assert_allowed(&session, &pull, &cwd, REFRESH);
    assert_allowed(&session, &fast_forward, &cwd, REFRESH);
    // A program the repository picks keeps both reviewed: Git builds the
    // merge message before it decides to fast-forward, and verifies a signed
    // tag there with `gpg.program`.
    session.config(&["gpg.program", "/tmp/gpg"]);
    assert_reviewed(&session, &pull, &cwd);
    assert_reviewed(&session, &fast_forward, &cwd);
    session.config(&["--unset-all", "gpg.program"]);
    // Signing the merge commit keeps the merge pull reviewed; a fast-forward
    // writes no commit.
    std::fs::write(
        &global,
        format!("{USER_CONFIG}[commit]\n\tgpgsign = true\n"),
    )
    .unwrap();
    assert_reviewed(&session, &pull, &cwd);
    assert_allowed(&session, &fast_forward, &cwd, REFRESH);
    // A signature check runs the program on every pull.
    std::fs::write(
        &global,
        format!("{USER_CONFIG}[merge]\n\tverifySignatures = true\n"),
    )
    .unwrap();
    assert_reviewed(&session, &pull, &cwd);
    assert_reviewed(&session, &fast_forward, &cwd);
}

/// `git fetch origin && git merge --ff-only origin/main` is a fast-forward
/// pull split in two. The merge reaches no remote, so it needs only the work
/// tree half of the pull proof, and a commit hook, commit signing or
/// `pull.rebase` (which `git merge` never reads) leave it quiet. Most cases
/// run in the linked worktree, which shares the main checkout's config, hooks
/// and remote-tracking refs, so a merge the proof refuses is not also taken
/// by the workspace sandbox.
#[test]
fn a_fast_forward_merge_of_origin_is_a_proven_refresh() {
    let session = session("merge-fast-forward");
    let wt = session.worktree.clone();
    let p = session.primary.display().to_string();
    let merge = "git merge --ff-only origin/main";
    let split = "git fetch origin && git merge --ff-only origin/main";
    session.config(&["branch.fix/report-lane.remote", "origin"]);
    session.config(&["branch.fix/report-lane.merge", "refs/heads/fix/report-lane"]);
    // A fetch of the branch records its remote-tracking ref.
    git(
        &session.home,
        &session.primary,
        &["update-ref", "refs/remotes/origin/fix/report-lane", "HEAD"],
    );
    for command in [
        merge.to_owned(),
        split.to_owned(),
        "git fetch origin fix/report-lane && git merge --ff-only origin/fix/report-lane 2>&1 | tail -3"
            .to_owned(),
        "git merge --ff-only @{u}".to_owned(),
        "git fetch origin && git merge --ff-only @{upstream}".to_owned(),
        // The main checkout behind `git -C` sits outside the shell's directory.
        format!("git -C {p} merge --ff-only origin/main"),
        format!("git -C {p} fetch origin && git -C {p} merge --ff-only origin/main"),
    ] {
        assert_allowed(&session, &command, &wt, REFRESH);
    }
    // A Git read after the merge falls to the read floor, which the local
    // write proof settles, or the workspace sandbox runs it in the linked
    // worktree; either way it runs without review.
    let followed = session.evaluate_at(
        "git merge -q --ff-only origin/main && git log --oneline -1",
        &wt,
    );
    assert!(
        matches!(
            followed.minimum_action.as_str(),
            "allow" | "sandbox-required"
        ),
        "{} {}",
        followed.minimum_action,
        followed.reason_code
    );
    // In the main checkout the proven merge runs directly, as the pull does,
    // rather than in the workspace sandbox that would cut the fetch off.
    for command in [merge, split] {
        assert_allowed(&session, command, &session.primary, REFRESH);
    }
    for (key, value) in [
        ("pull.rebase", "true"),
        ("branch.fix/report-lane.rebase", "true"),
        ("commit.gpgsign", "true"),
    ] {
        session.config(&[key, value]);
        assert_allowed(&session, split, &wt, REFRESH);
        session.config(&["--unset-all", key]);
    }
    for hook in ["pre-commit", "commit-msg", "post-commit", "post-checkout"] {
        let path = session.primary.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_allowed(&session, split, &wt, REFRESH);
        std::fs::remove_file(path).unwrap();
    }
    for tail in [
        // Every option other than quiet keeps the review, as does a ref that
        // is not origin's.
        "merge origin/main",
        "merge --ff origin/main",
        "merge --ff-only --no-ff origin/main",
        "merge --ff-only -s ours origin/main",
        "merge --ff-only -X theirs origin/main",
        "merge --ff-only --no-verify origin/main",
        "merge --ff-only -S origin/main",
        "merge --ff-only --squash origin/main",
        "merge --ff-only --autostash origin/main",
        "merge --ff-only --verify-signatures origin/main",
        "merge --ff-only main",
        "merge --ff-only upstream/main",
        "merge --ff-only FETCH_HEAD",
        "merge --ff-only origin/main@{1}",
    ] {
        assert_reviewed(&session, &format!("git fetch origin && git {tail}"), &wt);
        // The merge alone may still be a local write that its own proof
        // settles, but never this refresh.
        assert_ne!(
            reason(&session, &format!("git {tail}"), &wt).as_deref(),
            Some(REFRESH),
            "{tail}"
        );
    }
    for command in [
        "git fetch evil && git merge --ff-only origin/main",
        "git fetch origin && git merge --ff-only origin/main && git merge --ff-only origin/next",
        "git pull --ff-only && git merge --ff-only origin/main",
        "git merge --ff-only origin/main && git fetch origin",
        "git fetch origin && git -c core.hooksPath=/tmp/hooks merge --ff-only origin/main",
        "git fetch origin && GIT_DIR=/tmp/other.git git merge --ff-only origin/main",
        "git fetch origin && git merge --ff-only origin/main | cat tracked.txt",
    ] {
        assert_reviewed(&session, command, &wt);
    }
    // A read screened before the merge could follow a link it checks out.
    assert_ne!(
        reason(
            &session,
            "git merge --ff-only origin/main && cat tracked.txt",
            &wt
        )
        .as_deref(),
        Some(REFRESH)
    );
    let elsewhere = session.org.display().to_string();
    for (key, value) in [
        ("core.fsmonitor", "/tmp/monitor"),
        ("core.worktree", elsewhere.as_str()),
        ("core.hooksPath", ".githooks"),
        ("filter.fixture.smudge", "id"),
        ("hook.post-merge.command", "id"),
        ("merge.verifySignatures", "true"),
        ("gpg.program", "/tmp/gpg"),
        ("branch.fix/report-lane.mergeoptions", "--verify-signatures"),
        ("remote.origin.promisor", "true"),
        ("submodule.vendor.url", "https://github.com/acme/vendor.git"),
        ("lfs.customtransfer.fixture.path", "/tmp/transfer"),
    ] {
        session.config(&[key, value]);
        assert_ne!(
            reason(&session, merge, &wt).as_deref(),
            Some(REFRESH),
            "{key}"
        );
        assert_reviewed(&session, split, &wt);
        session.config(&["--unset-all", key]);
    }
    // An automatic stash is reapplied with a merge, which runs the driver.
    session.config(&["merge.fixture.driver", "sh -c id %O %A %B"]);
    assert_allowed(&session, split, &wt, REFRESH);
    session.config(&["merge.autoStash", "true"]);
    assert_reviewed(&session, split, &wt);
    session.config(&["--unset-all", "merge.autoStash"]);
    session.config(&["--unset-all", "merge.fixture.driver"]);
    // The upstream a bare `@{u}` names must be origin's.
    session.config(&["branch.fix/report-lane.remote", "evil"]);
    assert_ne!(
        reason(&session, "git merge --ff-only @{u}", &wt).as_deref(),
        Some(REFRESH)
    );
    session.config(&["branch.fix/report-lane.remote", "origin"]);
    for hook in [
        "post-merge",
        "post-index-change",
        "reference-transaction",
        "pre-auto-gc",
    ] {
        let path = session.primary.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_ne!(
            reason(&session, merge, &wt).as_deref(),
            Some(REFRESH),
            "{hook}"
        );
        assert_reviewed(&session, split, &wt);
        std::fs::remove_file(path).unwrap();
    }
    // A post-merge hook keeps even the merge alone under review.
    let path = session.primary.join(".git/hooks/post-merge");
    executable_hook(&path);
    assert_reviewed(&session, merge, &wt);
    std::fs::remove_file(path).unwrap();
    assert_allowed(&session, split, &wt, REFRESH);
}
