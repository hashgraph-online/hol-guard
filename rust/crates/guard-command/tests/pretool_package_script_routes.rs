#![cfg(unix)]

//! `npm|pnpm|bun run <script>` and `npm|pnpm test` get a narrow protected-sink
//! receipt only for a script body that sink runs. Any other body is still an
//! untrusted package script: it never proceeds unprotected, and never gets a
//! receipt its sink would refuse.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};

const PACKAGE_TEST: &str = "native_package_test_readonly_containment_required";
const NODE_TOOL: &str = "native_node_tool_readonly_containment_required";
const NODE_BUILD: &str = "native_node_build_output_containment_required";
const WORKSPACE: &str = "native_workspace_containment_required";
const HARNESSES: [&str; 3] = ["omp", "claude-code", "codex"];

fn root() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-package-scripts-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

/// A repository with `scripts` as its manifest scripts and the given
/// `node_modules` entrypoints installed.
fn project(root: &Path, name: &str, scripts: serde_json::Value, entries: &[&str]) -> PathBuf {
    let project = root.join(name);
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    let manifest = json!({"name": name, "scripts": scripts});
    std::fs::write(project.join("package.json"), manifest.to_string()).unwrap();
    for entry in entries {
        let entry = project.join("node_modules").join(entry);
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(entry, "").unwrap();
    }
    project
}

fn classify(cwd: &Path, harness: &str, command: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    )
}

const VITE: &str = "vite/bin/vite.js";
const FIXTURE: &str = include_str!("../../../../tests/fixtures/package-script-routes.v1.json");

/// Each case's receipt matches what the sink does with the same manifest:
/// the narrow reason when it runs the script, the generic route otherwise.
/// `tests/test_guard_package_script_parity.py` runs the sinks on these cases.
#[test]
fn package_script_receipts_match_the_sinks() {
    let root = root();
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let command = case["command"].as_str().unwrap();
        let entries: Vec<&str> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .collect();
        let cwd = project(&root, name, case["scripts"].clone(), &entries);
        let expected = case["reason"].as_str();
        for harness in HARNESSES {
            let result = classify(&cwd, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {name}");
            assert_ne!(result.minimum_action, "allow", "{harness}: {name}");
            match expected {
                Some(reason) if cfg!(target_os = "macos") => assert_eq!(
                    (result.minimum_action.as_str(), result.reason_code.as_str()),
                    ("sandbox-required", reason),
                    "{harness}: {name}"
                ),
                Some(_) => {}
                None => {
                    assert!(
                        ![PACKAGE_TEST, NODE_TOOL, NODE_BUILD]
                            .contains(&result.reason_code.as_str()),
                        "{harness}: {name}: {}",
                        result.reason_code
                    );
                    if result.minimum_action == "sandbox-required" {
                        assert_eq!(result.reason_code, WORKSPACE, "{harness}: {name}");
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// The script is read from the directory the command runs in, up to the
/// workspace root, as the sink reads it.
#[test]
fn a_subdirectory_run_reads_the_nearest_manifest() {
    let root = root();
    let ws = project(&root, "mono", json!({"build": "tsc -p ."}), &[]);
    let web = ws.join("web");
    std::fs::create_dir_all(&web).unwrap();
    std::fs::write(
        web.join("package.json"),
        json!({"scripts": {"build": "vite build"}}).to_string(),
    )
    .unwrap();
    let entry = web.join("node_modules").join(VITE);
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(entry, "").unwrap();
    for harness in HARNESSES {
        let narrow = classify(&ws, harness, "cd web && npm run build 2>&1 | tail -5");
        let root_build = classify(&ws, harness, "npm run build 2>&1 | tail -5");
        let cd = format!("cd {} && npm run build 2>&1 | tail -5", web.display());
        let cd = classify(&ws, harness, &cd);
        assert_eq!(cd.decision, "deny", "{harness}");
        assert_ne!(root_build.minimum_action, "allow", "{harness}");
        assert_ne!(root_build.reason_code, NODE_BUILD, "{harness}");
        if cfg!(target_os = "macos") {
            assert_eq!(cd.reason_code, NODE_BUILD, "{harness}");
        }
        // A relative `cd` is never peeled; it keeps its review.
        assert_ne!(narrow.minimum_action, "allow", "{harness}");
    }
    let _ = std::fs::remove_dir_all(root);
}
