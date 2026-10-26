//! The routine-runner verdict: the one shape it accepts, and every condition
//! it refuses on.

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use super::*;

const INSTALLED_VERSION: &str = "9.1.0";
const DECLARED_VERSION: &str = "^9.0.0";

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

/// An eslint install the verdict accepts: declared in
/// `devDependencies`, installed under `node_modules`, pinned by one lockfile.
fn workspace() -> TempDir {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    write(
        &root.join("package.json"),
        &format!(r#"{{"devDependencies": {{"eslint": "{DECLARED_VERSION}"}}}}"#),
    );
    write(
        &root.join("node_modules/eslint/package.json"),
        &format!(r#"{{"name": "eslint", "version": "{INSTALLED_VERSION}"}}"#),
    );
    write(
        &root.join("node_modules/eslint/bin/eslint.js"),
        "#!/usr/bin/env node\n",
    );
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}"}}}}}}"#
        ),
    );
    dir
}

fn evidence(path: &Path) -> PackageExecutionFileEvidence {
    PackageExecutionFileEvidence {
        path: path.to_string_lossy().into_owned(),
        resolved_path: Some(path.to_string_lossy().into_owned()),
        status: "available",
        file_identity: Some("dev:1:ino:2".to_owned()),
        content_hash: Some("a".repeat(64)),
    }
}

fn target() -> PackageIntentTarget {
    PackageIntentTarget {
        ecosystem: "npm".to_owned(),
        package_name: Some("eslint".to_owned()),
        raw_spec: "eslint".to_owned(),
        requested_specifier: None,
        source_url: None,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

fn intent(root: &Path) -> PackageIntent {
    PackageIntent {
        package_manager: "npx".to_owned(),
        intent_kind: "execute",
        command_tokens: vec!["npx".to_owned(), "eslint".to_owned(), ".".to_owned()],
        redacted_command: "npx eslint .".to_owned(),
        targets: vec![target()],
        manifest_paths: Vec::new(),
        lockfile_paths: Vec::new(),
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: vec![LocalPackageExecutionEvidence {
            manager_name: "npx".to_owned(),
            path_source: "path".to_owned(),
            effective_cwd: root.to_string_lossy().into_owned(),
            cwd_source: "workspace".to_owned(),
            manager_is_guard_shim: false,
            local_only_requested: false,
            context_hash: "b".repeat(64),
            package_name: Some("eslint".to_owned()),
            executable_name: Some("eslint".to_owned()),
            declared_version: Some(DECLARED_VERSION.to_owned()),
            manager: Some(evidence(&root.join("node_modules/.bin/npx"))),
            local_executable: Some(evidence(&root.join("node_modules/eslint/bin/eslint.js"))),
            manifests: vec![evidence(&root.join("package.json"))],
            lockfiles: vec![evidence(&root.join("package-lock.json"))],
            typescript_launch: None,
        }],
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
        routine_local_runner: false,
    }
}

#[test]
fn a_runner_bound_to_local_project_state_is_routine() {
    let dir = workspace();
    assert!(routine_local_runner(&intent(dir.path())));
}

#[test]
fn every_routine_runner_name_qualifies_and_no_other_does() {
    for name in ["eslint", "jest", "tsc", "vitest"] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        write(
            &root.join("package.json"),
            &format!(r#"{{"dependencies": {{"{name}": "{DECLARED_VERSION}"}}}}"#),
        );
        write(
            &root.join(format!("node_modules/{name}/package.json")),
            &format!(r#"{{"name": "{name}", "version": "{INSTALLED_VERSION}"}}"#),
        );
        write(&root.join(format!("node_modules/{name}/bin/run.js")), "\n");
        write(
            &root.join("package-lock.json"),
            &format!(
                r#"{{"packages": {{"node_modules/{name}": {{"version": "{INSTALLED_VERSION}"}}}}}}"#
            ),
        );

        let mut value = intent(root);
        value.targets[0].raw_spec = name.to_owned();
        value.targets[0].package_name = Some(name.to_owned());
        let execution = &mut value.local_executions[0];
        execution.package_name = Some(name.to_owned());
        execution.executable_name = Some(name.to_owned());
        execution.local_executable = Some(evidence(
            &root.join(format!("node_modules/{name}/bin/run.js")),
        ));
        assert!(routine_local_runner(&value), "{name}");

        value.targets[0].raw_spec = "prettier".to_owned();
        value.local_executions[0].package_name = Some("prettier".to_owned());
        assert!(!routine_local_runner(&value), "{name}");
    }
}

#[test]
fn only_the_two_execute_managers_qualify() {
    let dir = workspace();
    let mut value = intent(dir.path());
    value.package_manager = "bunx".to_owned();
    assert!(routine_local_runner(&value));

    value.package_manager = "npm".to_owned();
    assert!(!routine_local_runner(&value));
}

#[test]
fn more_than_one_execution_or_target_is_not_routine() {
    let dir = workspace();

    let mut two_executions = intent(dir.path());
    let duplicate = two_executions.local_executions[0].clone();
    two_executions.local_executions.push(duplicate);
    assert!(!routine_local_runner(&two_executions));

    let mut two_targets = intent(dir.path());
    two_targets.targets.push(target());
    assert!(!routine_local_runner(&two_targets));

    let mut no_targets = intent(dir.path());
    no_targets.targets.clear();
    assert!(!routine_local_runner(&no_targets));
}

#[test]
fn a_target_that_drifts_from_the_execution_is_not_routine() {
    let dir = workspace();

    let mut renamed = intent(dir.path());
    renamed.targets[0].raw_spec = "eslint@9".to_owned();
    assert!(!routine_local_runner(&renamed));

    let mut pinned = intent(dir.path());
    pinned.targets[0].requested_specifier = Some("9.1.0".to_owned());
    assert!(!routine_local_runner(&pinned));

    let mut from_source = intent(dir.path());
    from_source.targets[0].source_kind = Some("git".to_owned());
    assert!(!routine_local_runner(&from_source));

    let mut from_url = intent(dir.path());
    from_url.targets[0].source_url = Some("https://example.test/eslint.tgz".to_owned());
    assert!(!routine_local_runner(&from_url));
}

#[test]
fn an_explicit_package_option_fetches_something_else() {
    let dir = workspace();

    for token in ["--package", "--package=eslint@8"] {
        let mut value = intent(dir.path());
        value.command_tokens.insert(1, token.to_owned());
        assert!(!routine_local_runner(&value), "{token}");
    }
}

#[test]
fn an_executable_that_is_not_the_package_is_not_routine() {
    let dir = workspace();
    let mut value = intent(dir.path());
    value.local_executions[0].executable_name = Some("eslint-config".to_owned());
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_version_naming_a_source_outside_the_registry_proves_nothing() {
    let dir = workspace();

    for declared in [
        "file:../eslint",
        "git+https://example.test/eslint.git",
        "git://example.test/eslint.git",
        "github:example/eslint",
        "http://example.test/eslint.tgz",
        "HTTPS://example.test/eslint.tgz",
    ] {
        let mut value = intent(dir.path());
        value.local_executions[0].declared_version = Some(declared.to_owned());
        assert!(!routine_local_runner(&value), "{declared}");
    }

    let mut undeclared = intent(dir.path());
    undeclared.local_executions[0].declared_version = None;
    assert!(!routine_local_runner(&undeclared));
}

#[test]
fn incomplete_evidence_is_not_evidence() {
    let dir = workspace();
    let root = dir.path();

    let mut missing_manager = intent(root);
    missing_manager.local_executions[0].manager = None;
    assert!(!routine_local_runner(&missing_manager));

    let mut unreadable_manager = intent(root);
    unreadable_manager.local_executions[0]
        .manager
        .as_mut()
        .unwrap()
        .status = "missing";
    assert!(!routine_local_runner(&unreadable_manager));

    let mut no_identity = intent(root);
    no_identity.local_executions[0]
        .manifests
        .get_mut(0)
        .unwrap()
        .file_identity = None;
    assert!(!routine_local_runner(&no_identity));

    let mut no_hash = intent(root);
    no_hash.local_executions[0]
        .lockfiles
        .get_mut(0)
        .unwrap()
        .content_hash = None;
    assert!(!routine_local_runner(&no_hash));

    let mut no_manifests = intent(root);
    no_manifests.local_executions[0].manifests.clear();
    assert!(!routine_local_runner(&no_manifests));

    let mut no_lockfiles = intent(root);
    no_lockfiles.local_executions[0].lockfiles.clear();
    assert!(!routine_local_runner(&no_lockfiles));
}

#[test]
fn an_executable_outside_the_package_directory_is_not_contained() {
    let dir = workspace();
    let root = dir.path();
    write(&root.join("node_modules/other/bin/eslint.js"), "\n");

    let mut value = intent(root);
    value.local_executions[0].local_executable =
        Some(evidence(&root.join("node_modules/other/bin/eslint.js")));
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_workspace_that_does_not_resolve_is_not_contained() {
    let dir = workspace();
    let mut value = intent(dir.path());
    value.local_executions[0].effective_cwd = dir
        .path()
        .join("does-not-exist")
        .to_string_lossy()
        .into_owned();
    assert!(!routine_local_runner(&value));
}

#[test]
fn an_incomplete_execution_context_withholds_the_verdict() {
    let dir = workspace();
    let mut value = intent(dir.path());
    value.execution_context_reason_codes = vec!["shell_context_incomplete".to_owned()];
    assert!(!routine_local_runner(&value));
}

#[test]
fn the_declared_pin_must_name_the_installed_package() {
    let dir = workspace();
    let root = dir.path();

    let mut other_pin = intent(root);
    other_pin.local_executions[0].declared_version = Some("^8.0.0".to_owned());
    assert!(!routine_local_runner(&other_pin));

    write(
        &root.join("package.json"),
        r#"{"peerDependencies": {"eslint": "^9.0.0"}}"#,
    );
    assert!(!routine_local_runner(&intent(root)));

    write(&root.join("package.json"), "{ not json");
    assert!(!routine_local_runner(&intent(root)));
}

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
fn a_file_past_the_read_limit_gives_no_text() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("package-lock.json");
    write(&path, "{\"packages\": {}}");
    let length = u64::try_from("{\"packages\": {}}".len()).unwrap();
    assert!(super::routine_local_runner::read_bounded(&path, length).is_some());
    assert!(super::routine_local_runner::read_bounded(&path, length - 1).is_none());
    assert!(
        super::routine_local_runner::read_bounded(&dir.path().join("missing"), length).is_none()
    );
}
