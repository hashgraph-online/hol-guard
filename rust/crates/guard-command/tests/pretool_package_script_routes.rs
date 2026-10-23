#![cfg(unix)]

//! A package-manager command that names a script gets a narrow protected-sink
//! receipt only for a script body that sink runs. That covers `npm|pnpm|bun|yarn
//! run <script>`, the bare `pnpm|yarn <script>`, and `npm|pnpm|yarn test`. Any
//! other body is still an untrusted package script: it never proceeds
//! unprotected, and never gets a receipt its sink would refuse.

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
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-package-scripts-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    HOME.with(|declared| {
        *declared.borrow_mut() = Some(home.to_str().unwrap().to_owned());
    });
    root
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

thread_local! {
    /// macOS keeps the temporary directory under `/private/var`, a screened
    /// system root these fixtures only leave through the private-temporary
    /// workspace proof, which reads the declared home to learn whose temporary
    /// directory it is. A home that does not exist has no owner, so every
    /// absolute operand under the fixture root would stay unproved there while
    /// the Linux `/tmp` root proves it without the home. The proof reads only
    /// the home's owner, so the home sits inside the fixture root this test
    /// built and goes away with it.
    static HOME: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn classify(cwd: &Path, harness: &str, command: &str) -> PreToolResultV1 {
    let home = HOME.with(|declared| declared.borrow().clone());
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.as_deref(),
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

/// A direct `vite build` keeps the build receipt only for an output directory
/// the build sink accepts: a `dist`, `build` or `out` directory next to the
/// workspace root or a package manifest. Any other `--outDir` would be refused
/// by the sink, so it takes the generic route instead.
#[test]
fn a_direct_build_keeps_the_receipt_only_for_an_accepted_output() {
    let root = root();
    let ws = project(&root, "direct", json!({}), &[VITE]);
    let entry = ws.join("node_modules").join(VITE);
    let accepted = [
        "vite build --outDir dist".to_string(),
        "bunx vite build --outDir=out".to_string(),
        format!("node {} build --outDir ./build", entry.display()),
    ];
    for command in &accepted {
        let result = classify(&ws, "omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(result.reason_code, NODE_BUILD, "{command}");
        }
    }
    let refused = [
        "vite build --outDir=/tmp/out".to_string(),
        "vite build --outDir /tmp/out".to_string(),
        "vite build --outDir=dist --outDir /tmp/dist".to_string(),
        "bunx vite build --outDir public".to_string(),
        "npx vite build --outDir=../dist".to_string(),
        "vite build --outDir src/dist".to_string(),
        format!("node {} build --outDir", entry.display()),
    ];
    for harness in HARNESSES {
        for command in &refused {
            let result = classify(&ws, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(result.reason_code, NODE_BUILD, "{harness}: {command}");
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// A `node_modules` link to another directory in the workspace still names a
/// local tool, which is the entry the sink resolves.
#[test]
fn a_linked_node_modules_inside_the_workspace_keeps_the_tool_route() {
    let root = root();
    let project = project(&root, "linked", json!({"lint": "eslint src"}), &[]);
    let store = project.join("store/node_modules/eslint/bin");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("eslint.js"), "").unwrap();
    std::os::unix::fs::symlink(
        project.join("store/node_modules"),
        project.join("node_modules"),
    )
    .unwrap();
    let result = classify(&project, "codex", "npm run lint");
    assert_ne!(result.decision, "allow");
    if cfg!(target_os = "macos") {
        assert_eq!(result.reason_code, NODE_TOOL);
    }
    let _ = std::fs::remove_dir_all(root);
}

/// A Vite config that names an output the sink cannot read stays on the
/// generic route. A literal output keeps the build receipt only when that
/// directory would pass the sink's admissibility checks.
#[test]
fn an_unverifiable_vite_config_output_does_not_take_the_build_receipt() {
    let root = root();
    let project = project(&root, "configured", json!({"build": "vite build"}), &[VITE]);
    std::fs::write(
        project.join("vite.config.js"),
        "export default { outDir: process.env.OUT }\n",
    )
    .unwrap();
    let unverifiable = classify(&project, "omp", "npm run build");
    assert_ne!(unverifiable.decision, "allow");
    assert_ne!(unverifiable.reason_code, NODE_BUILD);
    std::fs::write(
        project.join("vite.config.js"),
        "export default { outDir: 'site' }\n",
    )
    .unwrap();
    let literal = classify(&project, "omp", "npm run build");
    assert_ne!(literal.decision, "allow");
    if cfg!(target_os = "macos") {
        assert_eq!(literal.reason_code, NODE_BUILD);
    }
    std::fs::create_dir_all(project.join("site")).unwrap();
    std::fs::write(project.join("site/LOGO.PNG"), "").unwrap();
    let cased = classify(&project, "omp", "npm run build");
    assert_ne!(cased.decision, "allow");
    if cfg!(target_os = "macos") {
        assert_eq!(cased.reason_code, NODE_BUILD);
    }
    std::fs::write(project.join("site/.js"), "").unwrap();
    let bare_suffix = classify(&project, "omp", "npm run build");
    assert_ne!(bare_suffix.decision, "allow");
    assert_ne!(bare_suffix.reason_code, NODE_BUILD);
    std::fs::create_dir_all(project.join("server")).unwrap();
    std::fs::write(project.join("server/package.json"), "{}\n").unwrap();
    std::fs::write(
        project.join("vite.config.js"),
        "export default { outDir: 'server/public' }\n",
    )
    .unwrap();
    let through_a_package = classify(&project, "omp", "npm run build");
    assert_ne!(through_a_package.decision, "allow");
    assert_ne!(through_a_package.reason_code, NODE_BUILD);
    let _ = std::fs::remove_dir_all(root);
}
