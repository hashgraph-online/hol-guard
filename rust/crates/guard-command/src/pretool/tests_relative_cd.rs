#![cfg(unix)]

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
    }
}

fn allowed_in(
    root: &std::path::Path,
    command: &str,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let root = root.to_str().unwrap();
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

fn crate_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap()
}

#[test]
fn bare_relative_cd_needs_a_declared_environment_without_cdpath() {
    let root = crate_root();
    let clean = environment(&["HOME", "PATH"]);
    let cdpath = environment(&["CDPATH", "HOME", "PATH"]);
    for command in [
        "cd src && ls",
        "cd src/pretool && ls",
        "cd tests/support && ls",
    ] {
        assert!(allowed_in(&root, command, Some(&clean)), "{command}");
        assert!(
            !allowed_in(&root, command, None),
            "{command}: no environment"
        );
        assert!(
            !allowed_in(&root, command, Some(&cdpath)),
            "{command}: CDPATH"
        );
    }
}

#[test]
fn dotted_relative_cd_skips_cdpath_and_keeps_the_target_checks() {
    let root = crate_root();
    let cdpath = environment(&["CDPATH", "HOME", "PATH"]);
    for environment in [None, Some(&cdpath)] {
        assert!(allowed_in(&root, "cd ./src && ls", environment));
        for command in [
            "cd ./missing && ls",
            "cd ./.ssh && ls",
            "cd ./Cargo.toml && ls",
        ] {
            assert!(!allowed_in(&root, command, environment), "{command}");
        }
    }
}

#[test]
fn parent_directory_cd_is_never_proved() {
    // The shell resolves `..` against its logical $PWD, which can differ
    // from the reported cwd when the session was entered through a symlink.
    let root = crate_root().join("src");
    let clean = environment(&["HOME", "PATH"]);
    for command in [
        "cd .. && ls",
        "cd ../tests && ls",
        "cd ./pretool/.. && ls",
        "cd pretool/.. && ls",
    ] {
        assert!(!allowed_in(&root, command, Some(&clean)), "{command}");
    }
}

#[test]
fn relative_cd_through_a_symlink_is_not_proved() {
    // The system temporary directory lives under a reviewed root on macOS.
    let parent = crate_root().join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent
        .canonicalize()
        .unwrap()
        .join(format!("guard-relative-cd-{}", std::process::id()));
    std::fs::create_dir_all(root.join("real")).unwrap();
    std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
    let clean = environment(&["HOME", "PATH"]);
    let outcome = (
        allowed_in(&root, "cd real && ls", Some(&clean)),
        allowed_in(&root, "cd link && ls", Some(&clean)),
        allowed_in(&root, "cd ./link && ls", Some(&clean)),
    );
    std::fs::remove_dir_all(&root).unwrap();
    assert!(outcome.0);
    assert!(!outcome.1 && !outcome.2);
}
