//! The lockfile and manifest evidence behind the routine-runner verdict:
//! what the installed package has to say about itself, and what a lock
//! entry has to pin before it answers for the installed version.

use super::*;

#[test]
fn the_installed_manifest_must_identify_itself() {
    let dir = workspace();
    let root = dir.path();

    write(
        &root.join("node_modules/eslint/package.json"),
        r#"{"name": "eslint-fork", "version": "9.1.0"}"#,
    );
    assert!(!routine_local_runner(&intent(root)));

    write(
        &root.join("node_modules/eslint/package.json"),
        r#"{"name": "eslint"}"#,
    );
    assert!(!routine_local_runner(&intent(root)));
}

#[test]
fn every_lockfile_must_agree_with_the_installed_version() {
    let dir = workspace();
    let root = dir.path();

    write(
        &root.join("package-lock.json"),
        r#"{"packages": {"node_modules/eslint": {"version": "9.0.0"}}}"#,
    );
    assert!(!routine_local_runner(&intent(root)));

    // Two lockfiles that disagree leave no single locked version.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}"}}}}}}"#
        ),
    );
    write(
        &root.join("npm-shrinkwrap.json"),
        r#"{"packages": {"node_modules/eslint": {"version": "9.0.0"}}}"#,
    );
    let mut two = intent(root);
    two.local_executions[0]
        .lockfiles
        .push(evidence(&root.join("npm-shrinkwrap.json")));
    assert!(!routine_local_runner(&two));

    // A lockfile that names nothing at all leaves the version unlocked.
    write(&root.join("package-lock.json"), r#"{"packages": {}}"#);
    assert!(!routine_local_runner(&intent(root)));

    // A lockfile Guard cannot read fails closed even when another agrees.
    write(&root.join("package-lock.json"), "{ not json");
    assert!(!routine_local_runner(&intent(root)));
}

#[test]
fn a_bun_lockfile_is_read_as_jsonc() {
    let dir = workspace();
    let root = dir.path();
    fs::remove_file(root.join("package-lock.json")).unwrap();
    write(
        &root.join("bun.lock"),
        &format!(
            "{{\n  // bun writes comments into its text lockfile\n  \"packages\": {{\n    \"eslint\": [\"eslint@{INSTALLED_VERSION}\", {{}}, \"sha512-x\"]\n  }}\n}}\n"
        ),
    );

    let mut value = intent(root);
    value.local_executions[0].lockfiles = vec![evidence(&root.join("bun.lock"))];
    assert!(routine_local_runner(&value));

    write(
        &root.join("bun.lock"),
        "{\n  \"packages\": {\n    \"eslint\": [\"eslint@9.0.0\", {}, \"sha512-x\"]\n  }\n}\n",
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn the_installed_version_must_satisfy_the_declared_specifier() {
    let dir = workspace();
    let root = dir.path();
    write(
        &root.join("package.json"),
        r#"{"devDependencies": {"eslint": "~9.0.0"}}"#,
    );
    write(
        &root.join("node_modules/eslint/package.json"),
        &format!(r#"{{"name": "eslint", "version": "{INSTALLED_VERSION}"}}"#),
    );

    let mut value = intent(root);
    value.local_executions[0].declared_version = Some("~9.0.0".to_owned());
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_lockfile_that_omits_the_runner_binds_nothing() {
    let dir = workspace();
    let root = dir.path();

    // The second lockfile parses and names other packages, but never this
    // runner. The first one must not answer for it.
    write(
        &root.join("npm-shrinkwrap.json"),
        r#"{"packages": {"node_modules/other": {"version": "1.0.0"}}}"#,
    );
    let mut value = intent(root);
    value.local_executions[0]
        .lockfiles
        .push(evidence(&root.join("npm-shrinkwrap.json")));
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_lock_entry_outside_the_registry_proves_nothing() {
    let dir = workspace();
    let root = dir.path();

    // A linked workspace package is whatever that directory holds today.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}", "link": true}}}}}}"#
        ),
    );
    assert!(!routine_local_runner(&intent(root)));

    // So is a checkout resolved from a git remote.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}", "resolved": "git+ssh://git@example.test/eslint.git#abc"}}}}}}"#
        ),
    );
    assert!(!routine_local_runner(&intent(root)));

    // A registry tarball is the shape the declared pin actually describes.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}", "resolved": "https://registry.example.test/eslint.tgz"}}}}}}"#
        ),
    );
    assert!(routine_local_runner(&intent(root)));
}

#[test]
fn a_bun_entry_naming_a_checkout_is_not_a_release() {
    let dir = workspace();
    let root = dir.path();
    fs::remove_file(root.join("package-lock.json")).unwrap();
    write(
        &root.join("bun.lock"),
        "{\"packages\": {\"eslint\": [\"eslint@github:example/eslint#abc\", {}, \"\"]}}",
    );

    let mut value = intent(root);
    value.local_executions[0].lockfiles = vec![evidence(&root.join("bun.lock"))];
    assert!(!routine_local_runner(&value));
}
