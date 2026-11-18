//! `npx --no-install` and `npx --no` refuse to fetch anything, so the only
//! code they can start is the project's own installed bin. A second lockfile
//! that a different manager left behind with an older release says nothing
//! about that bin, so it no longer keeps the run out of the routine set. The
//! installed package still has to be the one `package.json` asks for.

use super::*;

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

#[test]
fn a_run_that_may_fetch_still_needs_every_lockfile_to_agree() {
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
        assert!(!routine_local_runner(&value), "{tokens:?}");
    }
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
