#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture};

/// A `head` or `tail` that names no count is the glance an agent takes at a
/// runner's output, and both programs bound it at ten lines on their own.
/// The chain reaches the same containment the counted spelling does, while a
/// stage that names a file or carries a count it cannot read keeps its
/// review.
#[test]
fn a_countless_head_or_tail_bounds_the_chain_like_its_counted_spelling() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for (command, reason) in [
            (
                format!("cd {project} && npx vitest run a.test.ts --reporter=dot --silent 2>&1 | grep -E \"Tests \" | head"),
                "native_vitest_readonly_containment_required",
            ),
            (
                format!("cd {project} && npx vitest run a.test.ts 2>&1 | head"),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx vitest run x 2>&1 | tail".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx vitest run x 2>&1 | head | tail".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                format!("cd {project}/web && pytest -q | head"),
                "native_pytest_readonly_containment_required",
            ),
            (
                "bun run typecheck 2>&1 | tail".into(),
                "native_node_tool_readonly_containment_required",
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
