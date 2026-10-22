#![cfg(windows)]

//! Windows routes the read-only Node tools — lint, typecheck and format
//! checks — into the same staged AppContainer run the Vite build takes. The
//! classifier admitted them on every platform long before the runner could
//! stage them there, so each one arrived as an ordinary review prompt: a
//! false positive, since nothing ran unprotected either way.
//!
//! The route is only as good as the install behind it. A staged run copies a
//! flat npm or Yarn classic `node_modules`, so a pnpm store, a Plug'n'Play
//! install or a missing entrypoint keeps the review prompt, as does a package
//! script, which the Windows sink does not run yet.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

const NODE_TOOL: &str = "native_node_tool_readonly_containment_required";
const REVIEW: &str = "native_command_review_required";
const PACKAGE_REVIEW: &str = "native_package_review";
/// The read-only tool runs the direct sink stages, in every spelling the
/// classifier admits.
const REPORTING: [&str; 7] = [
    "npx eslint src",
    "bunx eslint src",
    "eslint src",
    "npx tsc --noEmit",
    "pnpm exec tsc --noEmit",
    "npx prettier --check src",
    "node node_modules/eslint/bin/eslint.js src",
];

/// A repository with a flat install of each read-only tool, and the declared
/// home beside it.
fn project(marker: Option<&str>) -> (PathBuf, PathBuf) {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir().join(format!("guard-win-tool-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let project = root.join("app");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(
        project.join("package.json"),
        json!({"name": "app", "scripts": {"lint": "eslint src"}}).to_string(),
    )
    .unwrap();
    for entry in [
        "eslint/bin/eslint.js",
        "typescript/bin/tsc",
        "prettier/bin/prettier.cjs",
    ] {
        let path = project.join("node_modules").join(entry);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    if let Some(marker) = marker {
        let path = project.join("node_modules").join(marker);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    (project, home)
}

/// The review a run keeps when nothing contains it. A pnpm or Bun spelling is
/// the package manager's own command, so it keeps that review rather than the
/// generic one, exactly as it does on the other platforms.
fn review(command: &str) -> &'static str {
    if command.starts_with("pnpm ") || command.starts_with("bun ") {
        PACKAGE_REVIEW
    } else {
        REVIEW
    }
}

fn weighed(cwd: &Path, home: &Path, harness: &str, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_reporting_tool_run_is_contained_instead_of_reviewed() {
    let (project, home) = project(None);
    for command in REPORTING {
        for harness in ["omp", "claude-code", "codex"] {
            assert_eq!(
                weighed(&project, &home, harness, command),
                ("sandbox-required".to_string(), NODE_TOOL.to_string()),
                "{harness}: {command}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}

#[test]
fn a_run_that_rewrites_its_input_keeps_the_review_prompt() {
    let (project, home) = project(None);
    for command in [
        "npx eslint --fix src",
        "npx prettier --write src",
        "npx tsc",
        "npx tsc --noEmit --emitDeclarationOnly",
        "npx eslint --output-file=report.json src",
    ] {
        let (action, reason) = weighed(&project, &home, "claude-code", command);
        assert_ne!(reason, NODE_TOOL, "{command}");
        assert_ne!(action, "allow", "{command}");
    }
    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}

#[test]
fn a_package_script_keeps_the_review_prompt_the_windows_sink_still_needs() {
    // The Windows sink refuses package scripts, so routing one there would
    // trade a review prompt for a failed run.
    let (project, home) = project(None);
    for command in ["npm run lint", "npm.exe run lint", "pnpm run lint"] {
        let (action, reason) = weighed(&project, &home, "claude-code", command);
        assert_ne!(reason, NODE_TOOL, "{command}");
        assert_ne!(action, "allow", "{command}");
    }
    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}

#[test]
fn an_install_the_runner_cannot_stage_keeps_the_review_prompt() {
    for marker in [".pnpm/lock.yaml", ".modules.yaml"] {
        let (project, home) = project(Some(marker));
        for command in REPORTING {
            assert_eq!(
                weighed(&project, &home, "claude-code", command).1,
                review(command),
                "{marker}: {command}"
            );
        }
        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }
}

#[test]
fn a_tool_that_is_not_installed_locally_keeps_the_review_prompt() {
    let (project, home) = project(None);
    std::fs::remove_dir_all(project.join("node_modules/typescript")).unwrap();
    for command in ["npx tsc --noEmit", "pnpm exec tsc --noEmit"] {
        assert_eq!(
            weighed(&project, &home, "claude-code", command).1,
            review(command),
            "{command}"
        );
    }
    // The tools that are still installed keep their contained route.
    assert_eq!(
        weighed(&project, &home, "claude-code", "npx eslint src").1,
        NODE_TOOL
    );
    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}
