//! `npx --no-install` and `npx --no` refuse to fetch anything, so the only
//! code they can start is the project's own installed bin, and they skip the
//! lockfile agreement check outright.
//!
//! A second lockfile that a different manager left behind with an older
//! release says nothing about that bin either way. It is now passed over on
//! every route, fetch-capable runs included, because a pin the manifest's own
//! range no longer admits cannot describe the installed tree. What the two
//! routes still differ on is a workspace with no usable lockfile at all: a run
//! that cannot fetch stays routine, a run that can does not. The installed
//! package still has to be the one `package.json` asks for.

use super::*;

#[test]
fn a_lockfile_outside_the_declared_range_no_longer_vetoes() {
    let dir = workspace();
    let root = dir.path();

    // A project that moved from pnpm to npm keeps the pnpm lockfile in the
    // tree. It pins a release the manifest's own range excludes, so it was
    // written against an older manifest and says nothing about the tree `npx`
    // would start. The npm lockfile beside it still pins the install.
    let stale = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^8.0.0\n        version: 8.57.0\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {integrity: sha512-x}\n";
    write(&root.join("pnpm-lock.yaml"), stale);
    let mut both = intent(root);
    both.local_executions[0]
        .lockfiles
        .push(evidence(&root.join("pnpm-lock.yaml")));
    assert!(routine_local_runner(&both));

    // A second lockfile that disagrees from *inside* the declared range is not
    // stale. It describes an install this manifest still allows, so the two
    // lockfiles genuinely conflict and the verdict stays refused.
    write(
        &root.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^9.0.0\n        version: 9.0.0\n\npackages:\n\n  eslint@9.0.0:\n    resolution: {integrity: sha512-x}\n",
    );
    assert!(!routine_local_runner(&both));

    // A workspace whose only lockfile is stale pins nothing at all.
    let value = only_lockfile(root, "pnpm-lock.yaml", stale);
    assert!(!routine_local_runner(&value));
}

/// The accepted eslint workspace plus a stale pnpm lockfile that pins an
/// older release than the one installed.
fn stale_second_lockfile(tokens: &[&str]) -> (TempDir, PackageIntent) {
    let dir = workspace();
    let root = dir.path();
    write(
        &root.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^8.0.0\n        version: 8.57.0\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {integrity: sha512-AAAA}\n",
    );
    let mut value = intent(root);
    value.command_tokens = tokens.iter().map(|token| (*token).to_owned()).collect();
    value.local_executions[0]
        .lockfiles
        .push(evidence(&root.join("pnpm-lock.yaml")));
    (dir, value)
}

#[test]
fn a_run_that_refuses_to_fetch_ignores_a_stale_second_lockfile() {
    for tokens in [
        &["npx", "--no-install", "eslint", "."][..],
        &["npx", "--no", "eslint", "."][..],
        &["npx", "--yes", "--no-install", "eslint", "."][..],
        &["npx", "--quiet", "--no", "--", "eslint", "."][..],
    ] {
        let (_dir, value) = stale_second_lockfile(tokens);
        assert!(routine_local_runner(&value), "{tokens:?}");
    }
}

/// A fetch-capable run used to be refused here purely because the abandoned
/// manager's lockfile disagreed. It is now accepted: the surviving lockfile
/// still has to pin the installed release, and the stale file's pin is one
/// the manifest's range excludes, so it corroborates nothing either way.
#[test]
fn a_run_that_may_fetch_also_passes_over_a_stale_second_lockfile() {
    for tokens in [
        &["npx", "eslint", "."][..],
        &["npx", "--yes", "eslint", "."][..],
        &["npx", "--no-install", "--yes", "eslint", "."][..],
        &["npx", "-y", "eslint", "--no-install"][..],
        // `--no` is npx's own option; bunx has no such switch.
        &["bunx", "--no", "eslint", "."][..],
    ] {
        let (_dir, mut value) = stale_second_lockfile(tokens);
        if tokens[0] == "bunx" {
            value.package_manager = "bunx".to_owned();
        }
        assert!(routine_local_runner(&value), "{tokens:?}");
    }
}

/// The relaxation above is bounded by the declared range. A second lockfile
/// that disagrees from *inside* that range describes an install this manifest
/// still admits, so the two files genuinely conflict about what is on disk and
/// a run that may fetch stays out of the routine set.
#[test]
fn a_run_that_may_fetch_still_needs_in_range_lockfiles_to_agree() {
    for tokens in [
        &["npx", "eslint", "."][..],
        &["npx", "--yes", "eslint", "."][..],
        &["bunx", "eslint", "."][..],
    ] {
        let (dir, mut value) = stale_second_lockfile(tokens);
        if tokens[0] == "bunx" {
            value.package_manager = "bunx".to_owned();
        }
        // `^9.0.0` admits 9.0.0, so this pin is a live claim about the tree.
        write(
            &dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^9.0.0\n        version: 9.0.0\n\npackages:\n\n  eslint@9.0.0:\n    resolution: {integrity: sha512-AAAA}\n",
        );
        assert!(!routine_local_runner(&value), "{tokens:?}");
    }
}

/// A run that may fetch still needs a lockfile that pins the install. When the
/// abandoned manager's file is the only one left, passing over it leaves the
/// runner unpinned, and only a run that refuses to fetch stays routine.
#[test]
fn a_run_that_may_fetch_needs_a_surviving_lockfile() {
    let (dir, value) = stale_second_lockfile(&["npx", "eslint", "."]);
    std::fs::remove_file(dir.path().join("package-lock.json")).unwrap();
    let mut only_stale = value.clone();
    only_stale.local_executions[0].lockfiles = vec![evidence(&dir.path().join("pnpm-lock.yaml"))];
    assert!(!routine_local_runner(&only_stale));

    let mut refuses_to_fetch = only_stale;
    refuses_to_fetch.command_tokens = ["npx", "--no-install", "eslint", "."]
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    assert!(routine_local_runner(&refuses_to_fetch));
}

#[test]
fn a_run_that_refuses_to_fetch_still_needs_the_declared_release_installed() {
    let (dir, value) = stale_second_lockfile(&["npx", "--no-install", "eslint", "."]);
    // The installed tree holds a release outside the declared range.
    write(
        &dir.path().join("node_modules/eslint/package.json"),
        r#"{"name": "eslint", "version": "8.57.0"}"#,
    );
    assert!(!routine_local_runner(&value));
    // And a package that is not the one declared.
    write(
        &dir.path().join("node_modules/eslint/package.json"),
        r#"{"name": "eslint-fork", "version": "9.1.0"}"#,
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_run_that_refuses_to_fetch_needs_no_lockfile_at_all() {
    let dir = workspace();
    fs::remove_file(dir.path().join("package-lock.json")).unwrap();
    let mut value = intent(dir.path());
    value.command_tokens = ["npx", "--no-install", "eslint", "."]
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    value.local_executions[0].lockfiles.clear();
    assert!(routine_local_runner(&value));
    value.command_tokens = ["npx", "eslint", "."]
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    assert!(!routine_local_runner(&value));
}
