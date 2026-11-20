#![cfg(unix)]
//! `rg -g 'dir/...'` with `dir` as the search target.
//!
//! Ripgrep matches a path-shaped glob against the path it prints with the
//! working directory stripped, so a search rooted below that directory sees
//! paths that still carry the root's own name. The proof walks the root and
//! renders the same path, so such a glob narrows the search as it does for
//! ripgrep instead of leaving it unmodeled.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// A checkout whose test folder holds ordinary suites and, below them, a
/// hidden credential fixture a glob can still reach. The root stays below
/// the target directory: `$TMPDIR` on macOS resolves under `/private/var`,
/// which the sensitive-root screen rejects.
fn project() -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-glob-under-search-root")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    git(&project, &["init", "--quiet"]);
    write(project.join("src/app.ts"), "export const app = 1;\n");
    write(
        project.join("__tests__/app.test.ts"),
        "it('renders', () => {});\n",
    );
    write(
        project.join("__tests__/suites/panel.test.ts"),
        "it('renders', () => {});\n",
    );
    // Too large for the per-file fixture proof, so reaching it holds the
    // search rather than clearing it by reading.
    let vectors = format!("[{}\"end\"]\n", "\"case\",".repeat(60_000));
    write(
        project.join("__tests__/fixtures/.credentials.json"),
        &vectors,
    );
    git(&project, &["add", "src", "__tests__"]);
    let home = std::fs::canonicalize(home).unwrap();
    let project = home.join("project");
    (home, project)
}

/// The decision both shell harnesses reach, or "mixed" when they differ.
fn decision(home: &Path, cwd: &Path, command: &str) -> String {
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn a_path_glob_naming_the_search_root_narrows_the_search() {
    let (home, project) = project();
    for command in [
        // The glob spells the root's own name, as ripgrep's match base asks.
        "rg -l --glob '__tests__/*' renders __tests__",
        "rg -l --glob '__tests__/*.ts' renders __tests__",
        // The same glob with the working directory as the target, which was
        // already modeled, and a name-shaped glob, which needs no base.
        "rg -l --glob '__tests__/*' renders .",
        "rg -l --glob '*.test.ts' renders __tests__",
    ] {
        assert_eq!(decision(&home, &project, command), "allow", "{command}");
    }
}

#[test]
fn a_path_glob_that_reaches_the_hidden_fixture_still_holds_the_search() {
    let (home, project) = project();
    for command in [
        // `**` reaches past the suites into the credential fixture, which a
        // plain `rg` over the same folder passes over as hidden.
        "rg -l --glob '__tests__/**' renders __tests__",
        "rg -l --glob '__tests__/fixtures/*' renders __tests__",
    ] {
        let seen = decision(&home, &project, command);
        assert!(!seen.contains("allow"), "{command}: {seen}");
    }
}
