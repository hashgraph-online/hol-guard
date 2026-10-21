#![cfg(unix)]

//! `git merge --ff-only origin/<branch>` runs without review only while Git
//! resolves the target to origin's remote-tracking ref, no pager setting can
//! start a program, and, with Git LFS on, the checkout's LFS downloads reach
//! origin through the same transport the fetch proof accepts.

use crate::pretool_git_session_ops::{git, session, Session};
use std::path::Path;

const REFRESH: &str = "native_exact_safe_git_origin_refresh";
const MERGE: &str = "git merge --ff-only origin/main";
const SPLIT: &str = "git fetch origin && git merge --ff-only origin/main";

fn reason(session: &Session, command: &str, cwd: &Path) -> Option<String> {
    let result = session.evaluate_at(command, cwd);
    (result.minimum_action == "allow").then_some(result.reason_code)
}

fn assert_refresh(session: &Session, command: &str, cwd: &Path) {
    assert_eq!(
        reason(session, command, cwd).as_deref(),
        Some(REFRESH),
        "{command}"
    );
}

/// The merge alone may still settle as a local write, but never as this
/// refresh; the split form, which no local write proof takes, is reviewed.
fn assert_held(session: &Session, cwd: &Path, label: &str) {
    assert_ne!(
        reason(session, MERGE, cwd).as_deref(),
        Some(REFRESH),
        "{label}"
    );
    assert_eq!(reason(session, SPLIT, cwd), None, "{label}");
}

#[test]
fn a_ref_that_shadows_origins_branch_keeps_the_merge_reviewed() {
    let session = session("merge-ff-shadowed-ref");
    let wt = session.worktree.clone();
    let repo = |arguments: &[&str]| git(&session.home, &session.primary, arguments);
    assert_refresh(&session, MERGE, &wt);
    assert_refresh(&session, SPLIT, &wt);
    // Git resolves `origin/main` to the first of `refs/origin/main`, a tag
    // and a local branch before the remote-tracking ref.
    for shadow in [
        "refs/origin/main",
        "refs/tags/origin/main",
        "refs/heads/origin/main",
    ] {
        repo(&["update-ref", shadow, "HEAD"]);
        assert_held(&session, &wt, shadow);
        repo(&["update-ref", "-d", shadow]);
    }
    // An upstream with no remote-tracking ref resolves to nothing.
    session.config(&["branch.fix/report-lane.remote", "origin"]);
    session.config(&["branch.fix/report-lane.merge", "refs/heads/missing"]);
    assert_ne!(
        reason(&session, "git merge --ff-only @{u}", &wt).as_deref(),
        Some(REFRESH)
    );
    repo(&["update-ref", "refs/remotes/origin/missing", "HEAD"]);
    assert_refresh(&session, "git merge --ff-only @{u}", &wt);
    assert_refresh(&session, MERGE, &wt);
}

#[test]
fn a_pager_the_merge_or_fetch_would_start_keeps_the_review() {
    let session = session("merge-ff-pager");
    let wt = session.worktree.clone();
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull --ff-only origin main");
    assert_refresh(&session, &pull, &session.org);
    session.config(&["pager.merge", "sh -c id"]);
    assert_held(&session, &wt, "pager.merge");
    assert_ne!(
        reason(&session, &pull, &session.org).as_deref(),
        Some(REFRESH)
    );
    session.config(&["pager.merge", "false"]);
    assert_refresh(&session, SPLIT, &wt);
    session.config(&["--unset-all", "pager.merge"]);
    session.config(&["pager.pull", "true"]);
    assert_ne!(
        reason(&session, &pull, &session.org).as_deref(),
        Some(REFRESH)
    );
    // `git merge` never reads the pull's pager.
    assert_refresh(&session, SPLIT, &wt);
    session.config(&["--unset-all", "pager.pull"]);
    // The fetch's pager keeps the split reviewed; the merge alone fetches
    // nothing.
    session.config(&["pager.fetch", "sh -c id"]);
    assert_eq!(reason(&session, SPLIT, &wt), None);
    assert_refresh(&session, MERGE, &wt);
}

#[test]
fn with_git_lfs_on_the_merge_needs_the_fetch_transport_proof() {
    let session = session("merge-ff-lfs");
    let wt = session.worktree.clone();
    let unsafe_transport = [
        ("credential.helper", "!sh -c id"),
        (
            "remote.origin.url",
            "https://git.example.invalid/acme/app.git",
        ),
        (
            "url.ssh://git@evil.example/.insteadOf",
            "https://github.com/",
        ),
    ];
    // Without LFS the merge reaches no remote, so the transport is not read.
    for (key, value) in unsafe_transport {
        session.config(&[key, value]);
        assert_refresh(&session, MERGE, &wt);
        restore(&session, key);
    }
    // The filter `git lfs install` writes smudges what the fast-forward
    // checks out from origin's LFS endpoint, with Git's credentials.
    std::fs::write(
        session.home.join(".gitconfig"),
        "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\
         \tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\
         \trequired = true\n",
    )
    .unwrap();
    assert_refresh(&session, MERGE, &wt);
    assert_refresh(&session, SPLIT, &wt);
    for (key, value) in unsafe_transport {
        session.config(&[key, value]);
        assert_held(&session, &wt, key);
        restore(&session, key);
    }
    // LFS takes its endpoint, and how it authenticates there, from its own
    // keys rather than origin's URL.
    for (key, value) in [
        ("lfs.url", "https://lfs.example.invalid/acme/app"),
        ("lfs.pushurl", "https://lfs.example.invalid/acme/app"),
        (
            "remote.origin.lfsurl",
            "https://lfs.example.invalid/acme/app",
        ),
        ("lfs.https://lfs.example.invalid/.access", "basic"),
    ] {
        session.config(&[key, value]);
        assert_held(&session, &wt, key);
        session.config(&["--unset-all", key]);
    }
    // So can a `.lfsconfig` in the work tree.
    let lfsconfig = wt.join(".lfsconfig");
    std::fs::write(&lfsconfig, "[lfs]\n\turl = https://lfs.example.invalid/\n").unwrap();
    assert_held(&session, &wt, ".lfsconfig");
    std::fs::remove_file(&lfsconfig).unwrap();
    assert_refresh(&session, MERGE, &wt);
}

/// Put back the fixture's origin URL, or drop a key it never had.
fn restore(session: &Session, key: &str) {
    if key == "remote.origin.url" {
        session.config(&[key, "https://github.com/example-org/app-portal.git"]);
    } else {
        session.config(&["--unset-all", key]);
    }
}
