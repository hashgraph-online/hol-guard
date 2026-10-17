//! Upstream Pi ships `ls`, `find` and `grep` built-ins with the same names-only
//! and bounded-search semantics as Oh My Pi. They get the same proofs; Pi has
//! no `task`, `eval`, `glob` or bookkeeping tools, so those stay reviewed.
#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

struct Fixture {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
    project: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-pi-tools")
        .join(format!("{}-{name}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    for file in [
        "project/src/main.rs",
        "project/README.md",
        "clean/a.txt",
        "secret-dir/.env",
        ".ssh/id_rsa",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic fixture\n").unwrap();
    }
    Fixture {
        root,
        home,
        project,
    }
}

fn run(fixture: &Fixture, harness: &str, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn pi_listings_and_searches_get_the_bounded_proofs() {
    let f = fixture("proofs");
    for (tool, input, reason) in [
        ("ls", json!({}), "native_omp_directory_listing"),
        (
            "ls",
            json!({"path": "src", "limit": 500}),
            "native_omp_directory_listing",
        ),
        (
            "find",
            json!({"pattern": "**/*.rs", "path": ".", "limit": 1000}),
            "native_omp_directory_listing",
        ),
        (
            "grep",
            json!({"pattern": "fn main", "path": "src", "glob": "*.rs", "ignoreCase": true,
                   "literal": false, "context": 2, "limit": 100}),
            "native_bounded_search_scope",
        ),
        (
            "grep",
            json!({"pattern": "fixture", "path": "~/clean"}),
            "native_bounded_search_scope",
        ),
    ] {
        let result = run(&f, "pi", tool, input.clone());
        assert!(allowed(&result), "{tool} {input}: {}", result.reason_code);
        assert_eq!(result.reason_code, reason, "{tool} {input}");
    }
}

#[test]
fn pi_keeps_review_for_secrets_escapes_and_unmodeled_input() {
    let f = fixture("review");
    for (tool, input) in [
        ("ls", json!({"path": "~/.ssh"})),
        ("ls", json!({"path": "/etc"})),
        ("ls", json!({"path": ".", "limit": 1_000_000})),
        ("ls", json!({"path": ".", "follow": true})),
        ("find", json!({"pattern": "../../.ssh/*", "path": "."})),
        ("find", json!({"pattern": "*", "path": "~/.ssh"})),
        // The root is ordinary, but the walk reaches a sensitive child.
        (
            "find",
            json!({"pattern": "**/*", "path": "~", "hidden": true}),
        ),
        ("find", json!({"pattern": "*", "path": "~"})),
        ("grep", json!({"pattern": "x", "path": "~/secret-dir"})),
        (
            "grep",
            json!({"pattern": "x", "path": "~/clean", "glob": "/etc/*"}),
        ),
        (
            "grep",
            json!({"pattern": "x", "path": "~/clean", "context": -1}),
        ),
        (
            "grep",
            json!({"pattern": "x", "path": "~/clean", "ignoreCase": "yes"}),
        ),
        (
            "grep",
            json!({"pattern": "x", "path": "~/clean", "other": "value"}),
        ),
    ] {
        let result = run(&f, "pi", tool, input.clone());
        assert!(!allowed(&result), "{tool} {input}: {}", result.reason_code);
    }
}

#[test]
fn omp_only_tools_stay_reviewed_for_pi() {
    let f = fixture("omp-only");
    for (tool, input) in [
        (
            "task",
            json!({"tasks": [{"agent": "task", "task": "Summarize"}]}),
        ),
        ("wait", json!({})),
        (
            "todo",
            json!({"tasks": [{"agent": "task", "task": "Summarize"}]}),
        ),
        ("glob", json!({"path": "."})),
        ("eval", json!({"code": "1", "language": "js"})),
    ] {
        let result = run(&f, "pi", tool, input.clone());
        assert!(!allowed(&result), "{tool} {input}: {}", result.reason_code);
    }
    // Other harnesses keep their prior review for these tool names.
    assert!(!allowed(&run(&f, "codex", "ls", json!({"path": "."}))));
}

#[test]
fn omp_learn_stays_reviewed_before_it_runs() {
    // guard-runtime releases a `learn` result after execution because this
    // review means a person approved the call. Revisit that before allowing it here.
    let f = fixture("omp-learn");
    for input in [
        json!({"memory": "Run the project tests with cargo test before pushing."}),
        json!({"memory": "Run the project tests before pushing.", "context": "Code review turn"}),
        // A skill is a file later runs read; writing one stays a person's call.
        json!({
            "memory": "Run the project tests before pushing.",
            "skill": {
                "action": "create",
                "name": "project-tests",
                "description": "How to run this project's tests.",
                "body": "# Project tests\n\nRun the suite from the repository root."
            }
        }),
    ] {
        let result = run(&f, "omp", "learn", input.clone());
        assert_eq!(result.minimum_action, "review", "{input}");
        assert_eq!(
            result.reason_code, "native_pre_tool_unknown_review",
            "{input}"
        );
    }
}

#[test]
fn eval_code_that_is_not_a_constant_points_to_the_bash_tool() {
    let f = fixture("omp-eval-subprocess");
    let code = "const { spawnSync } = await import('node:child_process'); \
                display(spawnSync('bun', ['scripts/report.ts']).status);";
    for harness in ["omp", "pi"] {
        let result = run(&f, harness, "eval", json!({"code": code, "language": "js"}));
        assert_eq!(result.minimum_action, "review", "{harness}");
        assert_eq!(
            result.reason_code, "native_pre_tool_unknown_review",
            "{harness}"
        );
        assert!(
            result.reason.contains("bash tool"),
            "{harness}: {}",
            result.reason
        );
    }
    // Other tools Guard cannot check keep the general reason.
    let result = run(
        &f,
        "omp",
        "learn",
        json!({"memory": "Run the project tests before pushing."}),
    );
    assert!(!result.reason.contains("eval"), "{}", result.reason);
}
