#![cfg(unix)]

//! Session work beside a linked worktree: a new sibling worktree from a
//! routed checkout, a refresh of `origin` before it, and a fetch inside the
//! linked sibling. Every shape that could run a program, write outside home
//! or check out an unproven reference stays reviewed.

use crate::pretool_git_session_ops::{executable_hook, session, Session};
use std::path::Path;

const WORKTREE_ADD: &str = "native_exact_safe_worktree_add";
const REFRESH: &str = "native_exact_safe_git_origin_refresh";

fn assert_allow_at(session: &Session, cwd: &Path, command: &str, reason_code: &str) {
    let result = session.evaluate_at(command, cwd);
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", reason_code),
        "{command}"
    );
}

fn assert_reviewed(session: &Session, command: &str) {
    let result = session.evaluate_at(command, &session.org);
    assert_ne!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

#[test]
fn routed_sibling_worktree_add_from_origin_is_quiet() {
    let session = session("sibling-add");
    let primary = session.primary.display().to_string();
    let destination = session.home.join("app-portal-fix-ga4");
    let destination = destination.display();
    for command in [
        format!("git -C {primary} worktree add {destination} -b feat/ga4-goal origin/main"),
        format!(
            "git -C {primary} worktree add {destination} -b feat/ga4-goal origin/main 2>&1 | tail -1"
        ),
        format!(
            "git -C {primary} fetch origin main --quiet; git -C {primary} worktree add {destination} -b feat/ga4-goal origin/main 2>&1 | tail -1"
        ),
        format!("git -C {primary} worktree add --detach {destination} origin/main"),
    ] {
        assert_allow_at(&session, &session.org, &command, WORKTREE_ADD);
    }
    assert_allow_at(
        &session,
        &session.primary,
        "git worktree add ../app-portal-ga4 -b feat/ga4-goal origin/main",
        WORKTREE_ADD,
    );
}

#[test]
fn sibling_worktree_add_keeps_unproven_shapes_reviewed() {
    let session = session("sibling-refused");
    let primary = session.primary.display().to_string();
    let fresh = session.home.join("app-portal-ga4").display().to_string();
    let home_name = session.home.file_name().unwrap().to_str().unwrap();
    // Outside home and outside every temporary root. On macOS the session
    // home sits in `/tmp`, whose sticky shared root admits a fresh checkout
    // beside home (`pretool_git_worktree_session`), so the build directory
    // stands in for an ordinary directory outside home on every host.
    let outside = std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .unwrap()
        .join(format!("{home_name}-outside"));
    std::fs::create_dir_all(session.home.join(".config")).unwrap();
    std::fs::create_dir_all(session.primary.join(".github")).unwrap();
    std::fs::create_dir_all(session.home.join("app-portal-full")).unwrap();
    std::fs::write(session.home.join("app-portal-full/notes.txt"), "kept\n").unwrap();
    for destination in [
        outside,
        session.home.join(".config/app-portal-ga4"),
        session.home.join(".app-portal-ga4"),
        session.primary.join(".github/workflows"),
        session.home.join("app-portal-full"),
    ] {
        assert_reviewed(
            &session,
            &format!(
                "git -C {primary} worktree add {} -b feat/ga4-goal origin/main",
                destination.display()
            ),
        );
    }
    for reference in [
        "upstream/main",
        "HEAD~1",
        "origin/main~1",
        "@{u}",
        "FETCH_HEAD",
    ] {
        assert_reviewed(
            &session,
            &format!("git -C {primary} worktree add {fresh} -b feat/ga4-goal {reference}"),
        );
    }
    for command in [
        format!("git -C {primary} worktree add -- {fresh} -b feat/ga4-goal origin/main"),
        format!("git -C {primary} worktree add {fresh} -b feat/ga4-goal -- origin/main"),
        format!("git -C {primary} worktree add -b feat/ga4-goal -- {fresh} origin/main"),
        format!("git -C {primary} worktree add {fresh} -b -- origin/main"),
        format!("git -C {primary} worktree add -f {fresh} -b feat/ga4-goal origin/main"),
        format!("git -C {primary} worktree add {fresh} -b feat/ga4-goal origin/main 2>&1 | sh"),
        format!(
            "git -C {primary} fetch upstream main; git -C {primary} worktree add {fresh} -b feat/ga4-goal origin/main"
        ),
    ] {
        assert_reviewed(&session, &command);
    }
}

#[test]
fn sibling_worktree_add_stays_reviewed_with_repository_programs() {
    let session = session("sibling-programs");
    let primary = session.primary.display().to_string();
    let fresh = session.home.join("app-portal-ga4").display().to_string();
    let add = format!("git -C {primary} worktree add {fresh} -b feat/ga4-goal origin/main");
    let chain = format!("git -C {primary} fetch origin main; {add}");
    let hooks = session.home.join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let hooks = hooks.display().to_string();
    for (key, value) in [
        ("core.hooksPath", hooks.as_str()),
        ("core.fsmonitor", "/bin/true"),
        ("filter.fixture.smudge", "cat"),
        ("filter.lfs.process", "git-lfs filter-process"),
        ("credential.helper", "osxkeychain"),
        ("core.pager", "cat"),
    ] {
        session.config(&[key, value]);
        assert_reviewed(&session, &add);
        assert_reviewed(&session, &chain);
        session.config(&["--unset-all", key]);
    }
    let hook = session.primary.join(".git/hooks/post-checkout");
    executable_hook(&hook);
    assert_reviewed(&session, &add);
    assert_reviewed(&session, &chain);
    std::fs::remove_file(&hook).unwrap();
    assert_allow_at(&session, &session.org, &add, WORKTREE_ADD);
    assert_allow_at(&session, &session.org, &chain, WORKTREE_ADD);
}

/// The fetch can move `origin/main` to a tree the proof never read, so after
/// it only the filter the user's own `git lfs install` wrote may be set.
#[test]
fn fetch_before_worktree_add_admits_only_the_users_lfs_filter() {
    let session = session("sibling-filters");
    let primary = session.primary.display().to_string();
    let fresh = session.home.join("app-portal-ga4").display().to_string();
    let add = format!("git -C {primary} worktree add {fresh} -b feat/ga4-goal origin/main");
    let chain = format!("git -C {primary} fetch origin main --quiet; {add}");
    let global = session.home.join(".gitconfig");
    std::fs::write(
        &global,
        "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n",
    )
    .unwrap();
    assert_allow_at(&session, &session.org, &add, WORKTREE_ADD);
    assert_allow_at(&session, &session.org, &chain, WORKTREE_ADD);
    std::fs::write(&global, "[filter \"fixture\"]\n\tsmudge = cat\n").unwrap();
    // No attribute in the current tree names the filter, so the add alone
    // stays proven; after a fetch the tree is unknown.
    assert_allow_at(&session, &session.org, &add, WORKTREE_ADD);
    assert_reviewed(&session, &chain);
}

#[test]
fn fetch_inside_a_linked_sibling_worktree_is_quiet() {
    let session = session("sibling-fetch");
    let primary = session.primary.display().to_string();
    let linked = session.worktree.display().to_string();
    for command in [
        format!(
            "cd {linked} && git fetch origin fix/report-lane 2>&1 | tail -2 && git log origin/main --oneline -4"
        ),
        format!("cd {linked} && git fetch origin main"),
        format!("git -C {primary} fetch origin main 2>&1 | tail -2"),
        // A dry run reports the same refresh and updates no ref.
        format!("cd {linked} && git fetch --dry-run origin main"),
    ] {
        assert_allow_at(&session, &session.org, &command, REFRESH);
    }
    for command in [
        format!("cd {linked} && git fetch origin main 2>&1 | sh"),
        format!("cd {linked} && git fetch origin main 2>&1 | tail -2 | sh"),
        format!("cd {linked} && git fetch origin main 2>&1 | tee fetch.log"),
        format!("cd {linked} && git fetch upstream main 2>&1 | tail -2"),
        format!("cd {linked} && git fetch origin main 2>/dev/null"),
    ] {
        assert_reviewed(&session, &command);
    }
    executable_hook(&session.primary.join(".git/hooks/reference-transaction"));
    assert_reviewed(
        &session,
        &format!("cd {linked} && git fetch origin fix/report-lane 2>&1 | tail -2"),
    );
}

/// A proven `git worktree add` writes the new checkout, its administrative
/// files, a branch and that branch's upstream, never configuration a Git
/// read uses, so a read after it in the same command keeps its own proof.
#[test]
fn git_reads_after_a_proven_worktree_add_keep_their_proof() {
    let session = session("sibling-add-read");
    let add = "git worktree add ../app-review -b feat/review-goal origin/main";
    for command in [
        format!("{add} && git status --short"),
        format!("{add}; git status --short && git branch --show-current"),
    ] {
        let result = session.evaluate_at(&command, &session.primary);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        "git worktree add -f ../app-review -b feat/review-goal origin/main && git status --short"
            .to_string(),
        "git worktree add ../app-review -b feat/review-goal upstream/main && git status --short"
            .to_string(),
        format!("{add} && git config core.pager cat && git status --short"),
        format!("{add} && git -c core.pager=cat log -1"),
    ] {
        let result = session.evaluate_at(&command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    session.config(&["core.pager", "cat"]);
    let result = session.evaluate_at(&format!("{add} && git status --short"), &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}

fn fresh_temporary_leaf(label: &str) -> std::path::PathBuf {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-scratch-{label}-{unique}"))
}

fn assert_allowed_anywhere(session: &Session, cwd: &Path, command: &str) {
    let result = session.evaluate_at(command, cwd);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

/// Agents put a scratch checkout straight into `/tmp`, refresh `origin`
/// first and read inside it. The leaf does not exist yet, so no other user
/// can own the directory Git fills.
#[test]
fn worktree_add_directly_in_the_temporary_root_is_quiet() {
    let session = session("temp-leaf");
    let primary = session.primary.display().to_string();
    let fresh = fresh_temporary_leaf("leaf");
    let _cleanup = crate::git_helper_fixture::FixtureCleanup(fresh.clone());
    let fresh = fresh.display().to_string();
    let output = std::process::Command::new("git")
        .args(["-C", &primary, "rev-parse", "HEAD"])
        .output()
        .unwrap();
    let commit = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    for command in [
        format!("git -C {primary} worktree add -q --detach {fresh} {commit}"),
        format!("git -C {primary} worktree add -q --detach {fresh} origin/main"),
        format!("git -C {primary} worktree add {fresh} -b feat/scratch origin/main"),
    ] {
        assert_allow_at(&session, &session.org, &command, WORKTREE_ADD);
    }
    for command in [
        format!("git worktree add -q --detach {fresh} origin/main"),
        format!("git worktree add -q --detach {fresh} HEAD && cd {fresh} && git log -1 --format='%H %s'"),
        format!(
            "git fetch -q origin main && git worktree add -q --detach {fresh} origin/main \
             && cd {fresh} && git log -1 --format='%H %s'"
        ),
    ] {
        assert_allowed_anywhere(&session, &session.primary, &command);
    }
    assert_allowed_anywhere(
        &session,
        &session.org,
        &format!("git -C {primary} worktree add -q --detach {fresh} HEAD && cd {fresh} && git log -1 --format='%H %s'"),
    );
}

/// The same scratch checkout stays reviewed where the leaf already exists,
/// or where the repository could run a program while Git fills it.
#[test]
fn worktree_add_directly_in_the_temporary_root_keeps_its_protections() {
    let session = session("temp-leaf-refused");
    let primary = session.primary.display().to_string();
    let planted = fresh_temporary_leaf("planted");
    let _planted = crate::git_helper_fixture::FixtureCleanup(planted.clone());
    std::fs::create_dir(&planted).unwrap();
    assert_reviewed(
        &session,
        &format!(
            "git -C {primary} worktree add -q --detach {} origin/main",
            planted.display()
        ),
    );
    let hidden = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!(".guard-scratch-{}", std::process::id()));
    assert_reviewed(
        &session,
        &format!(
            "git -C {primary} worktree add -q --detach {} origin/main",
            hidden.display()
        ),
    );
    let fresh = fresh_temporary_leaf("programs");
    let _cleanup = crate::git_helper_fixture::FixtureCleanup(fresh.clone());
    let add = format!(
        "git -C {primary} worktree add -q --detach {} origin/main",
        fresh.display()
    );
    let chain = format!(
        "git -C {primary} fetch -q origin main && {add} && cd {} && git log -1",
        fresh.display()
    );
    for (key, value) in [
        ("core.fsmonitor", "/bin/true"),
        ("credential.helper", "!/bin/sh -c true"),
        ("filter.fixture.smudge", "cat"),
    ] {
        session.config(&[key, value]);
        assert_reviewed(&session, &add);
        assert_reviewed(&session, &chain);
        session.config(&["--unset-all", key]);
    }
    let hook = session.primary.join(".git/hooks/post-checkout");
    executable_hook(&hook);
    assert_reviewed(&session, &add);
    assert_reviewed(&session, &chain);
}
