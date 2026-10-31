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

fn pairs(settings: &[(&str, &str)]) -> Vec<(String, String)> {
    settings
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn inert_settings_are_carried_into_the_plain_run_behind_them() {
    let (carried, program) = carried_program("CI=1 NODE_ENV=test vitest run").unwrap();
    assert_eq!(
        carried.settings,
        pairs(&[("CI", "1"), ("NODE_ENV", "test")])
    );
    assert_eq!(carried.behind, words(&["vitest", "run"]));
    assert_eq!(program, (words(&["vitest", "run"]), None, Kind::Vitest));
    let (carried, program) = carried_program("CI=true timeout 30 node --test").unwrap();
    assert_eq!(carried.behind, words(&["timeout", "30", "node", "--test"]));
    assert_eq!(
        program,
        (words(&["node", "--test"]), Some(30), Kind::NodeTest)
    );
}

#[test]
fn a_plain_data_setting_is_dropped_and_carries_nothing() {
    let (carried, program) = carried_program("REPORT_DIR=/tmp/r npm test").unwrap();
    assert!(carried.settings.is_empty());
    assert_eq!(carried.behind, words(&["npm", "test"]));
    assert_eq!(program.2, Kind::Package);
}

#[test]
fn a_command_with_nothing_to_carry_is_not_a_carried_run() {
    // A plain run has nothing to carry, and settings alone run nothing.
    assert_eq!(carried_program("vitest run"), None);
    assert_eq!(carried_program("CI=1"), None);
}

#[test]
fn a_chain_or_redirection_is_not_one_command() {
    assert!(one_command("python3 -c 'print(1)'"));
    assert!(one_command("timeout 20 pytest -q"));
    for command in [
        "cd x && python3 -c 0",
        "pytest; echo done",
        "pytest -q | tail -5",
        "pytest -q > report.txt",
        "pytest -q 2>&1",
        "pytest -q &",
    ] {
        assert!(!one_command(command), "{command}");
    }
}
