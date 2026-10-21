#![cfg(windows)]

//! Windows hands a harness the resolved image, so the same build arrives as
//! `node.exe` where Linux sees `node`. The receipt a command gets must not
//! depend on that spelling: the direct build sink parses the program name the
//! same way, and a package script keeps the review prompt either way.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};

const NODE_BUILD: &str = "native_node_build_output_containment_required";
const HARNESSES: [&str; 3] = ["omp", "claude-code", "codex"];

/// A repository with a flat install of Vite, which is the install the direct
/// build sink stages, and the declared home beside it.
fn project() -> (PathBuf, PathBuf) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("guard-win-build-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let project = root.join("app");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(
        project.join("package.json"),
        json!({"name": "app", "scripts": {"build": "vite build"}}).to_string(),
    )
    .unwrap();
    let entry = project.join("node_modules/vite/bin/vite.js");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(entry, "").unwrap();
    (project, home)
}

fn classify(cwd: &Path, home: &Path, harness: &str, command: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn weighed(cwd: &Path, home: &Path, harness: &str, command: &str) -> (String, String, String) {
    let result = classify(cwd, home, harness, command);
    (result.decision, result.minimum_action, result.reason_code)
}

#[test]
fn a_resolved_node_image_takes_the_same_route_as_the_bare_name() {
    let (project, home) = project();
    for harness in HARNESSES {
        let bare = weighed(
            &project,
            &home,
            harness,
            "node node_modules/vite/bin/vite.js build",
        );
        // Only harnesses whose shell runs the POSIX-quoted sink take the
        // build receipt on Windows; Codex has a PowerShell sink for the
        // Python profile alone, so its build keeps the review prompt.
        if harness == "codex" {
            assert_eq!(bare.2, "native_command_review_required", "{harness}");
            assert_ne!(bare.1, "sandbox-required", "{harness}");
        } else {
            assert_eq!(bare.2, NODE_BUILD, "{harness}");
        }
        for spelling in [
            "node.exe node_modules/vite/bin/vite.js build",
            "node.EXE node_modules/vite/bin/vite.js build",
        ] {
            assert_eq!(
                weighed(&project, &home, harness, spelling),
                bare,
                "{harness}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}

#[test]
fn a_resolved_package_manager_image_still_runs_a_package_script() {
    // The direct build sink does not run package scripts. `npm.exe run build`
    // is the same script `npm run build` is, so it keeps the review prompt
    // rather than taking the direct build receipt.
    let (project, home) = project();
    for harness in HARNESSES {
        let bare = weighed(&project, &home, harness, "npm run build");
        assert_ne!(bare.2, NODE_BUILD, "{harness}");
        for spelling in [
            "npm.exe run build",
            "pnpm.exe run build",
            "bun.exe run build",
        ] {
            let resolved = weighed(&project, &home, harness, spelling);
            assert_ne!(resolved.2, NODE_BUILD, "{harness}: {spelling}");
            assert_ne!(resolved.1, "allow", "{harness}: {spelling}");
        }
    }
    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}
