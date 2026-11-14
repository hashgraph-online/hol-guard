#![cfg(unix)]
//! `rg -g` over a checkout holding a committed, sensitive-named fixture.
//!
//! An inclusion glob makes ripgrep search hidden and ignored files as well,
//! so those are screened. A committed file that is neither hidden nor
//! ignored is one a plain `rg` over the same folder already searches, and
//! the glob only narrows the search to it, so it does not hold the search.
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

/// A home holding `project`, a repository whose test data is too large for
/// the per-file fixture proof. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the
/// sensitive-root screen rejects.
fn project() -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-glob-committed")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    git(&project, &["init", "--quiet"]);
    let vectors = format!("[{}\"end\"]\n", "\"case\",".repeat(60_000));
    write(project.join("src/app.rs"), "fn main() {}\n");
    write(project.join("testdata/secrets_vectors.json"), &vectors);
    write(project.join("hidden/.credentials.json"), &vectors);
    write(project.join("hidden/.cases/secrets_vectors.json"), &vectors);
    write(project.join("held/secrets_vectors.json"), &vectors);
    write(project.join("named/secrets_vectors.json"), &vectors);
    write(project.join(".gitignore"), "held/*.json\nnamed/\n");
    git(
        &project,
        &["add", "src", "testdata", "hidden", ".gitignore"],
    );
    git(&project, &["add", "-f", "held", "named"]);
    write(project.join("pending/secrets_vectors.json"), &vectors);
    write(project.join("pending/notes.txt"), "notes\n");
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
fn a_committed_visible_file_does_not_hold_a_glob_search() {
    let (home, project) = project();
    for command in [
        "rg -n render_vectors testdata/secrets_vectors.json",
        "rg -n render_vectors src testdata",
        "rg -n 'render_vectors|sha256' src testdata -g '*.json' | head -80",
        "rg -n render_vectors src testdata -g '*.rs' -g '*.json'",
    ] {
        assert_eq!(decision(&home, &project, command), "allow", "{command}");
    }
}

#[test]
fn files_only_the_glob_reaches_still_hold_it() {
    let (home, project) = project();
    for command in [
        // Hidden, under a hidden folder, ignored though committed, and not
        // committed at all.
        "rg -n render_vectors hidden -g '.credentials.json'",
        "rg -n render_vectors hidden -g 'secrets_vectors.json'",
        "rg -n render_vectors held -g '*.json'",
        "rg -n render_vectors pending -g '*.json'",
    ] {
        let seen = decision(&home, &project, command);
        assert!(!seen.contains("allow"), "{command}: {seen}");
    }
    // Plain `rg` searches an ignored folder named as its root, so the glob
    // adds nothing there; nor does it for an ordinary pending file.
    for command in [
        "rg -n render_vectors named -g '*.json'",
        "rg -n notes pending -g '*.txt'",
    ] {
        assert_eq!(decision(&home, &project, command), "allow", "{command}");
    }
}
