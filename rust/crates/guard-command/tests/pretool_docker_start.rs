//! Starting an existing Docker container runs without review: its mounts,
//! privileges, environment and network were fixed when it was created.
//! Creating, executing in, inspecting, stopping and removing containers, other
//! daemons and expanded names keep the review.
#![cfg(unix)]

use crate::git_helper_fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::path::PathBuf;

fn evaluate(label: &str, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let root =
        PathBuf::from("/tmp").join(format!("guard-docker-start-{label}-{}", std::process::id()));
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
fn starting_existing_containers_is_explicitly_benign() {
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "docker start app-test-pg",
            "docker start app-test-pg 2>&1 | tail -1",
            "docker start web db_1 cache.local",
            "docker start 4f3c2b1a9d8e",
            "docker container start web",
            "docker start web && docker ps",
        ] {
            let result = evaluate("allow", harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
            assert_eq!(
                result.reason_code, "native_exact_safe_container_start",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn container_creation_access_and_disruption_stay_reviewed() {
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "docker run -v /:/host alpine",
            "docker run --rm -it alpine sh",
            "docker create --privileged alpine",
            "docker exec web env",
            "docker inspect web",
            "docker -H tcp://build.example.com:2376 logs web",
            "docker cp web:/etc/passwd .",
            "docker compose up -d",
            "docker -H tcp://build.example.com:2376 start web",
            "docker --context production start web",
            "docker --config /tmp/docker-config start web",
            "DOCKER_HOST=tcp://build.example.com:2376 docker start web",
            "DOCKER_CONTEXT=production docker start web",
            "export DOCKER_HOST=tcp://build.example.com:2376; docker start web",
            "docker start $(docker ps -aq)",
            "docker start `cat names.txt`",
            "docker start $NAME",
            "docker start 'web*'",
            "docker start -a web",
            "docker start -i web",
            "docker start --checkpoint cp1 web",
            "docker start",
            "docker stop web",
            "docker restart web",
            "docker container stop web",
            "docker kill web",
            "docker rm -f web",
            "docker pause web",
            "docker update --restart always web",
            "echo web | docker start web",
            "./bin/docker start web",
        ] {
            assert_ne!(
                evaluate("review", harness, command).decision,
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
