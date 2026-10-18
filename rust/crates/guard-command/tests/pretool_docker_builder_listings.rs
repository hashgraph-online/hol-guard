//! Listing the local builders and the running compose projects prints what the
//! client's own configuration and the daemon's container labels already hold.
//! Bootstrapping a builder, removing one, and any listing that has to resolve a
//! compose project keep the review.
#![cfg(unix)]

use crate::git_helper_fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::path::PathBuf;

fn evaluate(label: &str, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let root = PathBuf::from("/tmp").join(format!(
        "guard-docker-listing-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let cwd = home.join("Code/org/app-portal");
    std::fs::create_dir_all(&cwd).unwrap();
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn builder_and_project_listings_run_without_review() {
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "docker buildx ls",
            "docker buildx ls --no-trunc",
            "docker buildx version",
            "docker compose ls",
            "docker compose ls -a",
            "docker compose ls --format json",
            "docker buildx ls | head -20",
        ] {
            assert_eq!(
                evaluate("allow", harness, command).decision,
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn builder_changes_and_resolved_projects_stay_reviewed() {
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "docker buildx inspect --bootstrap default",
            "docker buildx create --use",
            "docker buildx rm old-builder",
            "docker buildx prune -af",
            "docker buildx build .",
            "docker compose ps",
            "docker compose -f compose.yaml ls",
            "docker compose ls -f name=portal",
            "docker buildx ls --format json",
            "docker compose ls --project-directory /srv/app",
            "docker -H tcp://build.example.com:2376 buildx ls",
            "DOCKER_HOST=tcp://build.example.com:2376 docker buildx ls",
            "docker buildx ls $(cat builders.txt)",
        ] {
            assert_ne!(
                evaluate("review", harness, command).decision,
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
