#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// Home with a workspace repository. The root stays below the target
/// directory: on macOS `$TMPDIR` canonicalizes under `/private/var`, which the
/// sensitive-root screen rejects for every read.
fn fixture() -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-ref-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let repo = root.join("Code/app");
    for (path, content) in [
        (".git/HEAD", "ref: refs/heads/main\n"),
        (
            ".git/refs/heads/main",
            "0123456789abcdef0123456789abcdef01234567\n",
        ),
        (
            ".git/refs/heads/feature/login",
            "0123456789abcdef0123456789abcdef01234567\n",
        ),
        (
            ".git/refs/tags/v1.0.0",
            "0123456789abcdef0123456789abcdef01234567\n",
        ),
        (
            ".git/refs/remotes/origin/main",
            "0123456789abcdef0123456789abcdef01234567\n",
        ),
        (
            ".git/worktrees/feature/HEAD",
            "ref: refs/heads/feature/login\n",
        ),
        (
            ".git/config",
            "[remote \"origin\"]\n\turl = https://example.test/app.git\n",
        ),
        (".git/hooks/pre-commit", "#!/bin/sh\n"),
        (".git/logs/HEAD", "synthetic reflog\n"),
        (
            ".git/refs/stash",
            "0123456789abcdef0123456789abcdef01234567\n",
        ),
        (
            ".git/refs/heads/.hidden",
            "0123456789abcdef0123456789abcdef01234567\n",
        ),
        (".git/worktrees/feature/gitdir", "/elsewhere/.git\n"),
        (".git/refs/heads/feature/.hidden", "synthetic hidden ref\n"),
        (".github/.git/HEAD", "ref: refs/heads/main\n"),
    ] {
        let file = repo.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }
    std::fs::create_dir_all(root.join(".ssh/.git")).unwrap();
    std::fs::write(root.join(".ssh/.git/HEAD"), "ref: refs/heads/main\n").unwrap();
    (std::fs::canonicalize(&root).unwrap(), repo)
}

fn read(harness: &str, path: &Path, home: &Path, cwd: &Path) -> String {
    let (tool, input) = match harness {
        "omp" => ("read", json!({"path": path.to_str().unwrap()})),
        _ => ("Read", json!({"file_path": path.to_str().unwrap()})),
    };
    decide(harness, tool, input, home, cwd)
}

fn search(harness: &str, path: &Path, home: &Path, cwd: &Path) -> String {
    let (tool, input) = match harness {
        "omp" => (
            "grep",
            json!({"pattern": "ref", "path": path.to_str().unwrap()}),
        ),
        _ => (
            "Grep",
            json!({"pattern": "ref", "path": path.to_str().unwrap()}),
        ),
    };
    decide(harness, tool, input, home, cwd)
}

fn decide(harness: &str, tool: &str, input: serde_json::Value, home: &Path, cwd: &Path) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn git_ref_files_are_readable_without_opening_other_git_state() {
    let (home, repo) = fixture();
    let repo = std::fs::canonicalize(repo).unwrap();
    for harness in ["zcode", "claude-code", "omp"] {
        for path in [
            ".git/HEAD",
            ".git/refs/heads/main",
            ".git/refs/heads/feature/login",
            ".git/refs/tags/v1.0.0",
            ".git/refs/remotes/origin/main",
            ".git/worktrees/feature/HEAD",
        ] {
            assert_eq!(
                read(harness, &repo.join(path), &home, &repo),
                "allow",
                "{harness} {path}"
            );
        }
        for path in [
            ".git/config",
            ".git/hooks/pre-commit",
            ".git/logs/HEAD",
            ".git/refs/stash",
            ".git/refs/heads/.hidden",
            ".git/worktrees/feature/gitdir",
            ".github/.git/HEAD",
        ] {
            assert_ne!(
                read(harness, &repo.join(path), &home, &repo),
                "allow",
                "{harness} {path}"
            );
        }
        // A ref directory is not a ref document: reading or searching it
        // could reach a hidden child the file rule refuses.
        for path in [".git/refs/heads/feature", ".git/refs/heads"] {
            assert_ne!(
                read(harness, &repo.join(path), &home, &repo),
                "allow",
                "{harness} read {path}"
            );
            assert_ne!(
                search(harness, &repo.join(path), &home, &repo),
                "allow",
                "{harness} search {path}"
            );
        }
        assert_ne!(
            read(harness, &home.join(".ssh/.git/HEAD"), &home, &repo),
            "allow",
            "{harness} hidden parent"
        );
    }
}
