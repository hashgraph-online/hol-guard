#![cfg(unix)]
//! A program written by its full path is proven like its bare name when the
//! path is the very file the session's `PATH` finds for that name.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a project and two program folders, each with a stand-in
/// `python3`. The folders are not named `bin`, so the installed-launcher
/// check never admits them and only the `PATH` match can. The root stays
/// below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-path-lookup-program")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/.git")).unwrap();
    for folder in ["tools", "first"] {
        std::fs::create_dir_all(home.join(folder)).unwrap();
        let program = home.join(folder).join("python3");
        std::fs::write(&program, "#!/bin/sh\n").unwrap();
        set_executable(&program);
    }
    std::os::unix::fs::symlink(home.join("tools"), home.join("linked")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

fn environment(home: &Path, path: &str) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    }
}

fn action(
    home: &Path,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    command: &str,
) -> String {
    let cwd = home.join("project");
    let result = evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        environment,
    );
    format!("{} {}", result.minimum_action, result.reason_code)
}

#[test]
fn a_full_path_to_the_path_match_is_proven_like_the_bare_name() {
    let home = home();
    let tools = home.join("tools");
    let program = tools.join("python3");
    let program = program.to_str().unwrap();
    let path = format!("{}:/usr/bin:/bin", tools.display());
    let stamped = environment(&home, &path);
    for command in [
        "python3 --version".to_owned(),
        format!("{program} --version"),
        format!("{program} -V 2>&1"),
        format!("'{program}' --version"),
        format!("pwd && {program} --version"),
    ] {
        assert_eq!(
            action(&home, Some(&stamped), &command),
            "allow native_exact_safe_command",
            "{command}"
        );
    }
    // A `PATH` entry that links to the same folder finds the same file.
    let linked = environment(
        &home,
        &format!("{}:/usr/bin", home.join("linked").display()),
    );
    assert_eq!(
        action(&home, Some(&linked), &format!("{program} --version")),
        "allow native_exact_safe_command"
    );
}

#[test]
fn a_full_path_the_bare_name_would_not_run_keeps_its_review() {
    let home = home();
    let program = home.join("tools/python3");
    let program = program.to_str().unwrap();
    let probe = format!("{program} --version");
    let reviewed = |environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
                    command: &str| {
        assert!(
            !action(&home, environment, command).starts_with("allow"),
            "{command} with PATH {:?}",
            environment.map(|environment| &environment.path)
        );
    };
    // No stamp says what the bare name would find.
    reviewed(None, &probe);
    // Another folder ahead on `PATH` holds its own `python3`.
    let shadowed = environment(
        &home,
        &format!(
            "{}:{}",
            home.join("first").display(),
            home.join("tools").display()
        ),
    );
    reviewed(Some(&shadowed), &probe);
    // A relative entry resolves against the working directory.
    let relative = environment(&home, &format!("tools:{}", home.join("tools").display()));
    reviewed(Some(&relative), &probe);
    // The path must be spelled plainly, without `..`.
    let stamped = environment(&home, &home.join("tools").display().to_string());
    let climbing = format!(
        "{}/../tools/python3 --version",
        home.join("first").display()
    );
    reviewed(Some(&stamped), &climbing);
    // The shell handles bare `pwd` as a builtin, while an absolute spelling
    // executes an actual file. Never grant a synthetic executable the builtin
    // allow just because its name matches a first PATH entry.
    let synthetic_pwd = home.join("tools/pwd");
    std::fs::write(&synthetic_pwd, "#!/bin/sh\nexit 0\n").unwrap();
    set_executable(&synthetic_pwd);
    reviewed(Some(&stamped), synthetic_pwd.to_str().unwrap());
    // The bare name's own proof still decides what the program may do.
    reviewed(Some(&stamped), &format!("{program} script.py"));
}
