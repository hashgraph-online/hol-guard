use super::*;
use serde_json::Value;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn expand(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace("$ROOT", root)),
        Value::Array(items) => Value::Array(items.iter().map(|item| expand(item, root)).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, item)| (key.clone(), expand(item, root)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

#[test]
fn recorded_original_restricted_execution_outcomes() {
    let root = std::env::temp_dir().join(format!("guard-restricted-parity-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root.canonicalize().unwrap());
    let workspace = fixture.0.join("project");
    fs::create_dir_all(workspace.join("bin")).unwrap();
    fs::create_dir(workspace.join("sub")).unwrap();
    fs::write(workspace.join("pyproject.toml"), "").unwrap();
    let executable = workspace.join("bin/python");
    fs::write(&executable, "#!/usr/bin/python3\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let pytest_executable = workspace.join("bin/pytest");
    fs::write(&pytest_executable, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&pytest_executable, fs::Permissions::from_mode(0o755)).unwrap();
    // The recorded cases need `bin/python` and `bin/Python` to be different
    // files. On a case-insensitive volume (the macOS default) they are one
    // file, so the case-sensitive recording cannot be replayed there.
    if workspace.join("bin/PYTHON").exists() {
        return;
    }
    let upper_python = workspace.join("bin/Python");
    fs::write(&upper_python, "#!/usr/bin/python3\n").unwrap();
    fs::set_permissions(&upper_python, fs::Permissions::from_mode(0o755)).unwrap();
    let python_entrypoint = workspace.join("bin/py.test");
    fs::write(
        &python_entrypoint,
        format!("#!{}\n", upper_python.display()),
    )
    .unwrap();
    fs::set_permissions(&python_entrypoint, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(workspace.join("sub"), workspace.join("alias")).unwrap();
    let recorded: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/restricted_pytest_parity.json"
    ))
    .unwrap();
    for case in recorded["cases"].as_array().unwrap() {
        let input = expand(&case["input"], fixture.0.to_str().unwrap());
        let expected = expand(&case["expected"], fixture.0.to_str().unwrap());
        let operation = case["operation"].as_str().unwrap();
        assert_eq!(
            evaluate(operation, &input),
            expected,
            "operation={operation}, input={input}"
        );
    }
}

#[test]
fn user_home_comes_from_the_account_database() {
    assert_eq!(
        host_home_directory(),
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .and_then(|user| user.dir.canonicalize().ok())
    );
}
