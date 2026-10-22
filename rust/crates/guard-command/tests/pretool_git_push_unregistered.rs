#![cfg(unix)]
//! The push proof stays under review until a verdict is registered.
//!
//! This binary never calls `install_git_push_verdict`. The other push tests
//! share one process-wide `OnceLock`, so this check has to run alone.
#[path = "../../../test_support/unique_nanos.rs"]
mod unique_nanos;

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-push")
        .join(format!(
            "unregistered-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("ready")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

#[test]
fn no_push_is_proven_before_a_verdict_is_registered() {
    let home = home();
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["HOME".to_owned(), "PATH".to_owned()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    let cwd = home.join("ready");
    let result = evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": "git push origin main"}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    );
    assert_ne!(result.decision, "allow");
}
