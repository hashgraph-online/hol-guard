#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn fixture() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/contained-wrapper-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/web")).unwrap();
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn classify(
    root: &std::path::Path,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        Some(root.to_str().unwrap()),
        Some(root.join("project").to_str().unwrap()),
    )
}

#[test]
fn verified_cd_and_bounded_output_filters_reach_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode"] {
        for (command, reason) in [
            (
                format!("cd {project}/web && bunx vitest run x 2>&1 | tail -20"),
                "native_vitest_readonly_containment_required",
            ),
            (
                format!("cd {project} && bun run typecheck 2>&1 | tail -n 20"),
                "native_node_tool_readonly_containment_required",
            ),
            (
                format!("cd '{project}/web' && bun run test"),
                "native_package_test_readonly_containment_required",
            ),
            (
                format!("cd {project}/web && pytest -q | head -40"),
                "native_pytest_readonly_containment_required",
            ),
            (
                "bunx vitest run x 2>&1 | tail -20".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bun run build | tail -5".into(),
                "native_node_build_output_containment_required",
            ),
            (
                "node --test | head -n 50".into(),
                "native_node_test_readonly_containment_required",
            ),
            (
                "bunx --cwd web vitest run x".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx --cwd=web/ vitest run x".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx vitest run --testNamePattern='a b' 2>&1 | tail -5".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx vitest run -t 'renders (empty)' | tail -20".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "pytest -q tests/a\\ b.py | head -3".into(),
                "native_pytest_readonly_containment_required",
            ),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert_eq!(result.reason_code, reason, "{harness}: {command}");
            }
        }
    }
}

#[test]
fn other_wrappers_stay_out_of_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    let outside = root.join("outside");
    let outside = outside.to_str().unwrap();
    let parent = root.to_str().unwrap();
    for harness in ["omp", "zcode"] {
        for command in [
            format!("cd {project}/web && bunx vitest run x && rm -rf /"),
            format!("cd {project}/web && bunx vitest run x; ls"),
            format!("cd {project}/web && cd .. && bunx vitest run x"),
            format!("cd {outside} && bunx vitest run x"),
            format!("cd {parent} && bunx vitest run x"),
            format!("cd {project}/missing && bunx vitest run x"),
            "cd web && bunx vitest run x".into(),
            "cd /tmp && bunx vitest run x".into(),
            format!("cd {project}/web && git status"),
            format!("cd {project}/web && git add ."),
            format!("cd {project}/web && git commit -m wip"),
            "bunx vitest run x | tail -f".into(),
            "bunx vitest run x | tail -20 notes.txt".into(),
            "bunx vitest run x | tail -n 1234567".into(),
            "bunx vitest run x | sh".into(),
            "bunx vitest run x | tee out.txt".into(),
            "bunx vitest run x | tail -20 | sh".into(),
            "bunx vitest run x |& tail -20".into(),
            "bunx vitest run x 2>/dev/null | tail -20".into(),
            "bunx vitest run x > out.txt | tail -20".into(),
            "bunx vitest run x | FOO=1 tail -20".into(),
            "FOO=1 bunx vitest run x | tail -20".into(),
            "bunx vitest run x || tail -20".into(),
            "tail -20 | bunx vitest run x".into(),
            "bunx --cwd ../other vitest run x".into(),
            "bunx --cwd /etc vitest run x".into(),
            "bunx --cwd ~ vitest run x".into(),
            "bunx --cwd $HOME vitest run x".into(),
            "npx --cwd web vitest run x".into(),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness}: {command}"
            );
        }
    }
}
