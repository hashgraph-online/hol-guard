use super::*;

fn installed_python() -> Option<PathBuf> {
    guard_runtime_windows_process::trusted_install_roots()
        .into_iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("python3")
        })
        .map(|entry| entry.path().join("python.exe"))
        .find(|path| path.is_file())
}

fn workspace() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let workspace = canonical(directory.path()).unwrap();
    std::fs::write(workspace.join("test_calc.py"), "print('calc-ok')").unwrap();
    (directory, workspace)
}

fn plan(workspace: &Path, command: &[&str], search_path: &str) -> Value {
    prepare_inline(&json!({
        "command": command,
        "workspace": workspace,
        "cwd": workspace,
        "search_path": search_path,
    }))
}

#[test]
fn python_names_are_recognized() {
    for name in [
        "python",
        "python3",
        "PYTHON3.EXE",
        r"C:\Python\python3.12.exe",
    ] {
        assert!(python_name(name), "{name}");
    }
    for name in ["pythonw", "python3.x", "node", "py"] {
        assert!(!python_name(name), "{name}");
    }
}

#[test]
fn credential_and_bulky_paths_are_withheld() {
    let patterns: Vec<Regex> = guard_command::credential_patterns::patterns()
        .iter()
        .map(|pattern| Regex::new(pattern).unwrap())
        .collect();
    let withhold = withheld(&patterns);
    for path in [
        ".env",
        r"app\.ENV.local",
        r"keys\id.key",
        r"nested\.ssh",
        ".git",
        r"a\node_modules",
    ] {
        assert!(withhold(Path::new(path)), "{path}");
    }
    for path in ["test_calc.py", r"src\environment.py", "README.md"] {
        assert!(!withhold(Path::new(path)), "{path}");
    }
}

#[test]
fn script_outside_the_workspace_is_rejected() {
    let (_directory, workspace) = workspace();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("other.py"), "").unwrap();
    let script = outside.path().join("other.py");
    let response = plan(&workspace, &["python3", script.to_str().unwrap()], "");
    assert_eq!(response["reason_code"], INVALID, "{response}");
}

/// The runner starts in the staged copy of `cwd`, so only a relative script
/// path names the staged file; any other spelling could reach the live one.
#[test]
fn only_relative_scripts_below_the_cwd_are_planned() {
    let (_directory, workspace) = workspace();
    let nested = workspace.join("pkg");
    std::fs::create_dir(&nested).unwrap();
    let absolute = workspace.join("test_calc.py");
    for (cwd, script) in [
        (&workspace, absolute.to_str().unwrap()),
        (&nested, absolute.to_str().unwrap()),
        (&nested, "../test_calc.py"),
        (&nested, r"..\test_calc.py"),
    ] {
        let response = prepare_inline(&json!({
            "command": ["python3", script],
            "workspace": workspace,
            "cwd": cwd,
            "search_path": "",
        }));
        assert_eq!(response["reason_code"], INVALID, "{script}: {response}");
    }
}

#[test]
fn untrusted_first_interpreter_is_rejected() {
    let (_directory, workspace) = workspace();
    let bin = tempfile::tempdir().unwrap();
    std::fs::write(bin.path().join("python3.exe"), "").unwrap();
    let response = plan(
        &workspace,
        &["python3", "test_calc.py"],
        bin.path().to_str().unwrap(),
    );
    assert_eq!(response["reason_code"], UNAVAILABLE, "{response}");
}

#[test]
fn python3_falls_back_to_python_exe_in_the_same_directory() {
    let bin = tempfile::tempdir().unwrap();
    std::fs::write(bin.path().join("python.exe"), "").unwrap();
    let search_path = bin.path().to_str().unwrap();
    // The match is found, then rejected only because the directory is untrusted.
    let error = resolve_executable("python3", search_path).unwrap_err();
    assert!(
        error.message.contains("installed for all users"),
        "{}",
        error.message
    );
    let error = resolve_executable("node", search_path).unwrap_err();
    assert!(
        error.message.contains("could not be resolved"),
        "{}",
        error.message
    );
}

/// A virtualenv's Scripts holds only `python.exe`; the shell runs the
/// `python3` found later on PATH, and so does the plan.
#[test]
fn python3_later_on_path_wins_over_an_earlier_python_exe() {
    let venv = tempfile::tempdir().unwrap();
    std::fs::write(venv.path().join("python.exe"), "").unwrap();
    let install = tempfile::tempdir().unwrap();
    std::fs::write(install.path().join("python3.exe"), "").unwrap();
    let search_path = std::env::join_paths([venv.path(), install.path()]).unwrap();
    let search_path = search_path.to_str().unwrap();
    assert_eq!(
        locate("python3", search_path),
        Some(install.path().join("python3.exe"))
    );
    // Without a `python3` anywhere, the first `python.exe` stands in.
    std::fs::remove_file(install.path().join("python3.exe")).unwrap();
    std::fs::write(install.path().join("python.exe"), "").unwrap();
    assert_eq!(
        locate("python3", search_path),
        Some(venv.path().join("python.exe"))
    );
}

#[test]
fn launch_requires_known_options() {
    for arguments in [
        vec![COMMAND, "--", "python"],
        vec![
            COMMAND,
            "--workspace",
            ".",
            "--cwd",
            ".",
            "--timeout-seconds",
            "0",
            "--",
            "python",
        ],
        vec![
            COMMAND,
            "--workspace",
            ".",
            "--workspace",
            ".",
            "--cwd",
            ".",
            "--timeout-seconds",
            "5",
            "--",
            "python",
        ],
        vec![
            COMMAND,
            "--workspace",
            ".",
            "--cwd",
            ".",
            "--timeout-seconds",
            "5",
            "--output",
            "dist",
            "--",
            "python",
        ],
        vec![
            COMMAND,
            "--profile",
            "node-eval-readonly-v1",
            "--workspace",
            ".",
            "--cwd",
            ".",
            "--timeout-seconds",
            "5",
            "--",
            "node",
        ],
        vec![
            COMMAND,
            "--profile",
            "node-build-output-v1",
            "--workspace",
            ".",
            "--cwd",
            ".",
            "--timeout-seconds",
            "5",
            "--",
            "node",
        ],
        vec![
            COMMAND,
            "--workspace",
            ".",
            "--cwd",
            ".",
            "--timeout-seconds",
            "5",
            "--shell",
            "1",
            "--",
            "python",
        ],
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
        assert!(parse(&arguments).is_err());
    }
}

#[test]
fn installed_python_plans_and_runs_in_the_snapshot() {
    let Some(python) = installed_python() else {
        eprintln!("skipped: no Python installed under Program Files");
        return;
    };
    let (_directory, workspace) = workspace();
    let search_path = python.parent().unwrap().to_str().unwrap();
    let response = plan(&workspace, &["python3", "test_calc.py"], search_path);
    let value = &response["value"];
    assert_eq!(value["backend"], BACKEND, "{response}");
    assert_eq!(value["profile_version"], PROFILE);
    let command: Vec<String> = serde_json::from_value(value["command"].clone()).unwrap();
    assert_eq!(command[1], "test_calc.py");
    let workspace = workspace.to_string_lossy().into_owned();
    let mut arguments: Vec<String> = [
        COMMAND,
        "--workspace",
        &workspace,
        "--cwd",
        &workspace,
        "--timeout-seconds",
        "60",
        "--",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    arguments.extend(command);
    assert_eq!(launch(&arguments).unwrap(), 0);
}
