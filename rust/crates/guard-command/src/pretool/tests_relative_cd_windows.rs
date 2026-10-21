#![cfg(windows)]

use crate::pretool::*;

fn environment(names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    }
}

fn allowed_in(
    root: &str,
    command: &str,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    evaluate_pre_tool_with_execution_context(
        &CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        },
        Some(root),
        Some(root),
        None,
        execution_environment,
    )
    .is_ok_and(|decision| decision.minimum_action == "allow")
}

/// Agents report the ordinary drive path, not the verbatim canonical form.
fn drive_path(path: &std::path::Path) -> String {
    let canonical = path.canonicalize().unwrap();
    canonical
        .to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .to_owned()
}

#[test]
fn bare_relative_cd_is_proved_on_windows_without_cdpath() {
    let root = drive_path(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let clean = environment(&["HOME", "PATH"]);
    let cdpath = environment(&["CdPath", "HOME", "PATH"]);
    for command in ["cd src && ls", "cd src/pretool && ls", "cd ./src && ls"] {
        assert!(allowed_in(&root, command, Some(&clean)), "{command}");
    }
    assert!(!allowed_in(&root, "cd src && ls", None), "no environment");
    assert!(!allowed_in(&root, "cd src && ls", Some(&cdpath)), "CDPATH");
}

#[test]
fn relative_cd_keeps_windows_spelling_checks() {
    let root = drive_path(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let clean = environment(&["HOME", "PATH"]);
    let drive = &root[..2];
    for command in [
        "cd SRC && ls".to_owned(),
        "cd .. && ls".to_owned(),
        "cd src/.. && ls".to_owned(),
        r"cd src\pretool && ls".to_owned(),
        format!("cd {drive}src && ls"),
        "cd src:stream && ls".to_owned(),
        // Git Bash resolves these against its own root, not the cwd's drive.
        "cd /src && ls".to_owned(),
        "cd /tmp && ls".to_owned(),
        "cd //localhost/c$ && ls".to_owned(),
        "cd missing && ls".to_owned(),
    ] {
        assert!(!allowed_in(&root, &command, Some(&clean)), "{command}");
    }
}

#[test]
fn relative_cd_through_a_junction_is_not_proved() {
    let parent = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let root = std::path::PathBuf::from(drive_path(&parent))
        .join(format!("guard-relative-cd-{}", std::process::id()));
    std::fs::create_dir_all(root.join("real")).unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("link"))
        .arg(root.join("real"))
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let root_text = root.to_str().unwrap();
    let clean = environment(&["HOME", "PATH"]);
    let outcome = (
        allowed_in(root_text, "cd real && ls", Some(&clean)),
        allowed_in(root_text, "cd link && ls", Some(&clean)),
        allowed_in(root_text, "cd ./link && ls", Some(&clean)),
    );
    std::fs::remove_dir(root.join("link")).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert!(outcome.0);
    assert!(!outcome.1 && !outcome.2);
}
