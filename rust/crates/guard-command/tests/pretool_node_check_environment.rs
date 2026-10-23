#![cfg(unix)]
//! `node --check` proceeds only when no inherited Node option can load code.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a project with `app.js`. The root stays below the target
/// directory: `$TMPDIR` on macOS resolves under `/private/var`, which the
/// sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-node-check")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/.git")).unwrap();
    std::fs::write(home.join("project/app.js"), "console.log('ok');\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn environment(home: &Path, names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    }
}

fn decision(
    home: &Path,
    environment: &guard_contracts::GuardExecutionEnvironmentV1,
    command: &str,
) -> String {
    let cwd = home.join("project");
    evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(environment),
    )
    .decision
}

const CHECKS: &[&str] = &[
    "node --check app.js",
    "curl -fsS http://localhost:4173/app.js | node --check",
];

#[test]
fn syntax_checks_proceed_with_an_inert_node_environment() {
    let home = home();
    let plain = environment(&home, &["HOME", "PATH"]);
    for command in CHECKS {
        assert_eq!(decision(&home, &plain, command), "allow", "{command}");
    }
}

#[test]
fn inherited_node_preloads_keep_the_review() {
    let home = home();
    for name in [
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ] {
        let inherited = environment(&home, &["HOME", "PATH", name]);
        for command in CHECKS {
            assert_ne!(
                decision(&home, &inherited, command),
                "allow",
                "{name}: {command}"
            );
        }
    }
}
