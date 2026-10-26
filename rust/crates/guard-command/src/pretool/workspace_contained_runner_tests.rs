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
    std::fs::create_dir_all(ws.join("nested/deep")).unwrap();
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
        // Offline and cache-first runs fetch less than the prompt options
        // above, and printing less changes nothing the sandbox weighs.
        "npx --offline vite build",
        "npx --prefer-offline vitest run",
        "npx --prefer-online vite build",
        "npx --quiet vite build",
        "npx -q vite build",
        "npx --silent vitest run",
        "npx -s vite build",
        "npx -- vite build",
        "npx --offline -- vite build",
        "cd app && npx tsc --noEmit",
        // A workspace that hoists its dependencies to the root installs
        // nothing under the package a run steps into, and the runner finds
        // the root's binary from there, so the sandbox follows it up.
        "cd app && npx vite build",
        "cd nested/deep && npx vitest run",
        "cd app && bunx vite build",
        "cd app && npm exec vitest run",
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
    std::fs::create_dir_all(ws.join("app")).unwrap();
    std::fs::create_dir_all(ws.join("nested/deep")).unwrap();
    for command in [
        "npx cowsay hi",
        "bun x vite@5.0.0 build",
        "npx --yes cowsay hi",
        "npx -y serve .",
        "npx --yes vite@5.0.0 build",
        "bunx -y vite build",
        "npx --package=left-pad vite build",
        // An option that reaches past the project's own install, or that
        // hands the runner a program of its own, is not one of these.
        "npx --offline cowsay hi",
        "npx --ignore-existing vite build",
        "npx -c \"vite build\"",
        "npx -- cowsay hi",
        "npx ./node_modules/.bin/vite build",
        "bun x vite build && npx cowsay hi",
        // A tool no directory the runner reads has installed is still one it
        // would fetch.
        "cd app && npx cowsay hi",
        "cd nested/deep && npx serve .",
        "bun add left-pad",
        "bun install left-pad",
        // A manager's own local verb beside a runner proves nothing about
        // the package the runner fetches.
        "npm test && npx cowsay hi",
        "npm run build && bunx serve .",
        "pnpm test && npx --yes left-pad",
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
