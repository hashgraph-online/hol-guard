use super::workspace_contained_tests::{host, reason, workspace, CONTAINED};
use std::path::Path;

fn install_tool(directory: &Path, tool: &str) {
    let bin = directory.join("node_modules/.bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join(tool), "#!/bin/sh\n").unwrap();
}

#[test]
fn runners_of_installed_project_tools_run_in_the_workspace_sandbox() {
    let ws = workspace("runner-installed", true);
    install_tool(&ws, "vite");
    install_tool(&ws, "vitest");
    std::fs::create_dir_all(ws.join("app")).unwrap();
    install_tool(&ws.join("app"), "tsc");
    for command in [
        "bun x vite build",
        "bun x vite build 2>&1 | tail -20",
        "bunx vite build",
        "npx vitest run src/math.test.ts",
        "npx --no-install vitest run",
        // With the tool installed, answering npx's install prompt in advance
        // fetches nothing.
        "npx --yes vite build",
        "npx -y vite build",
        "cd app && npx tsc --noEmit",
    ] {
        let got = reason("omp", command, &ws, true);
        // macOS claims some of these with narrower node profiles first.
        if cfg!(target_os = "linux") && host() {
            assert_eq!(got, CONTAINED, "{command}");
        }
    }
}

#[test]
fn runners_that_could_fetch_a_package_keep_their_review() {
    let ws = workspace("runner-fetch", true);
    install_tool(&ws, "vite");
    for command in [
        "npx cowsay hi",
        "bun x vite@5.0.0 build",
        "npx --yes cowsay hi",
        "npx -y serve .",
        "npx --yes vite@5.0.0 build",
        "bunx -y vite build",
        "npx --package=left-pad vite build",
        "npx ./node_modules/.bin/vite build",
        "bun x vite build && npx cowsay hi",
        "cd app && npx vite build",
        "bun add left-pad",
        "bun install left-pad",
    ] {
        let got = reason("omp", command, &ws, true);
        assert_ne!(got, CONTAINED, "{command}");
        assert_ne!(got, "native_exact_safe_command", "{command}");
    }
}

#[test]
fn inline_python_reading_a_home_dotdir_file_keeps_its_review() {
    let ws = workspace("runner-python", false);
    let command = "python3 -c \"import json; print(sorted(json.load(open('/Users/nobody/.codex/plans/evidence.json'))))\"";
    for harness in ["cursor", "codex", "omp"] {
        let got = reason(harness, command, &ws, true);
        assert_ne!(got, "native_exact_safe_command", "{harness}");
    }
}
