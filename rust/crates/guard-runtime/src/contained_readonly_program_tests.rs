use super::*;

fn words(command: &[&str]) -> Vec<String> {
    command.iter().map(|word| (*word).to_owned()).collect()
}

fn project(manifest: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().canonicalize().unwrap();
    std::fs::write(workspace.join("package.json"), manifest).unwrap();
    (directory, workspace)
}

#[test]
fn a_package_managers_own_test_script_is_a_package_run() {
    assert_eq!(
        plain_program("npm test"),
        Some((words(&["npm", "test"]), None, Kind::Package))
    );
    assert_eq!(
        plain_program("timeout 30 pnpm run test"),
        Some((words(&["pnpm", "run", "test"]), Some(30), Kind::Package))
    );
    assert_eq!(plain_program("CI=1 npm test"), None);
}

#[test]
fn a_package_test_runs_as_the_runner_its_script_spells() {
    let (_directory, workspace) = project(r#"{"scripts":{"test":"node --test"}}"#);
    let (argv, kind) =
        package_test(&words(&["npm", "test", "--", "a.test.js"]), &workspace).unwrap();
    assert_eq!(argv, words(&["node", "--test", "a.test.js"]));
    assert_eq!(kind, Kind::NodeTest);
    let (_directory, workspace) = project(r#"{"scripts":{"test":"vitest run"}}"#);
    let (argv, kind) = package_test(&words(&["npm", "test"]), &workspace).unwrap();
    assert_eq!(argv, words(&["vitest", "run"]));
    assert_eq!(kind, Kind::Vitest);
}

#[test]
fn a_package_test_the_runner_cannot_read_is_refused() {
    for manifest in [
        r#"{"scripts":{"test":"node --test","pretest":"node setup.js"}}"#,
        r#"{"scripts":{"test":"node --test && rm -rf src"}}"#,
        r#"{"scripts":{"build":"tsc"}}"#,
        "not json",
    ] {
        let (_directory, workspace) = project(manifest);
        // The refusal keeps its own name, as Guard's own sink prints it.
        let failure = package_test(&words(&["npm", "test"]), &workspace).unwrap_err();
        assert_eq!(failure.reason, "package_test_invalid_command", "{manifest}");
    }
}
