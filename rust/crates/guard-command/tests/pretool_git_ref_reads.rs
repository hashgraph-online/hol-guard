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
            crate::unique_nanos::unique_nanos()
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
            // A credential-free repository config is plain settings.
            ".git/config",
        ] {
            assert_eq!(
                read(harness, &repo.join(path), &home, &repo),
                "allow",
                "{harness} {path}"
            );
        }
        for path in [
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

/// A linked worktree outside the home whose common git directory lives in a
/// sibling checkout, as with `git worktree add ../app-feature`.
fn linked_worktree_fixture() -> (PathBuf, PathBuf, PathBuf) {
    let (root, _) = fixture();
    let home = root.join("home");
    let parent = root.join("projects/app");
    let worktree = root.join("projects/app-feature");
    let admin = parent.join(".git/worktrees/app-feature");
    for (path, content) in [
        (
            parent.join(".git/HEAD"),
            "ref: refs/heads/main\n".to_owned(),
        ),
        (
            parent.join(".git/refs/heads/main"),
            "0123456789abcdef0123456789abcdef01234567\n".to_owned(),
        ),
        (
            parent.join(".git/config"),
            "[remote \"origin\"]\n\turl = https://example.test/app.git\n".to_owned(),
        ),
        (
            parent.join(".git/logs/HEAD"),
            "synthetic reflog\n".to_owned(),
        ),
        (admin.join("HEAD"), "ref: refs/heads/feature\n".to_owned()),
        (admin.join("commondir"), "../..\n".to_owned()),
        (
            admin.join("gitdir"),
            format!("{}\n", worktree.join(".git").display()),
        ),
        (
            worktree.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        ),
        (worktree.join("src/lib.rs"), "\n".to_owned()),
        (home.join("README.md"), "\n".to_owned()),
    ] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    (home, parent, worktree)
}

#[test]
fn linked_worktree_reads_refs_in_its_common_git_directory() {
    let (home, parent, worktree) = linked_worktree_fixture();
    for harness in ["zcode", "claude-code", "omp"] {
        for cwd in [worktree.clone(), worktree.join("src")] {
            for path in [
                ".git/HEAD",
                ".git/refs/heads/main",
                ".git/worktrees/app-feature/HEAD",
            ] {
                assert_eq!(
                    read(harness, &parent.join(path), &home, &cwd),
                    "allow",
                    "{harness} {path}"
                );
            }
            for path in [
                ".git/config",
                ".git/logs/HEAD",
                ".git/worktrees/app-feature/gitdir",
            ] {
                assert_ne!(
                    read(harness, &parent.join(path), &home, &cwd),
                    "allow",
                    "{harness} {path}"
                );
            }
        }
        // Without the worktree the sibling repository stays outside scope.
        assert_ne!(
            read(harness, &parent.join(".git/refs/heads/main"), &home, &home),
            "allow",
            "{harness} unrelated cwd"
        );
    }
}

#[test]
fn a_hidden_ancestor_does_not_hide_the_common_git_directory() {
    let (root, _) = fixture();
    let home = root.join("home");
    let parent = root.join(".projects/app");
    let worktree = root.join("projects/app-feature");
    let admin = parent.join(".git/worktrees/app-feature");
    for (path, content) in [
        (
            parent.join(".git/HEAD"),
            "ref: refs/heads/main\n".to_owned(),
        ),
        (
            parent.join(".git/refs/heads/main"),
            "0123456789abcdef0123456789abcdef01234567\n".to_owned(),
        ),
        (
            parent.join(".git/refs/heads/.hidden"),
            "0123456789abcdef0123456789abcdef01234567\n".to_owned(),
        ),
        (parent.join(".git/config"), "[core]\n".to_owned()),
        (admin.join("HEAD"), "ref: refs/heads/feature\n".to_owned()),
        (admin.join("commondir"), "../..\n".to_owned()),
        (
            worktree.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        ),
        (worktree.join("src/lib.rs"), "\n".to_owned()),
        (home.join("README.md"), "\n".to_owned()),
    ] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", worktree.join(".git").display()),
    )
    .unwrap();
    for harness in ["zcode", "claude-code", "omp"] {
        assert_eq!(
            read(harness, &parent.join(".git/HEAD"), &home, &worktree),
            "allow",
            "{harness} HEAD"
        );
        assert_eq!(
            read(
                harness,
                &parent.join(".git/refs/heads/main"),
                &home,
                &worktree
            ),
            "allow",
            "{harness} refs/heads/main"
        );
        assert_ne!(
            read(
                harness,
                &parent.join(".git/refs/heads/.hidden"),
                &home,
                &worktree
            ),
            "allow",
            "{harness} hidden ref"
        );
        assert_ne!(
            read(harness, &parent.join(".git/config"), &home, &worktree),
            "allow",
            "{harness} config"
        );
        assert_ne!(
            read(harness, &parent.join(".git/HEAD"), &home, &home),
            "allow",
            "{harness} unrelated cwd"
        );
    }
}

#[test]
fn a_named_pipe_git_metadata_file_does_not_grant_common_dir_reads() {
    for kind in ["dot-git", "commondir", "gitdir"] {
        let (home, parent, worktree) = linked_worktree_fixture();
        let marker = match kind {
            "dot-git" => worktree.join(".git"),
            "commondir" => parent.join(".git/worktrees/app-feature/commondir"),
            "gitdir" => parent.join(".git/worktrees/app-feature/gitdir"),
            _ => unreachable!(),
        };
        std::fs::remove_file(&marker).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&marker)
                .status()
                .unwrap()
                .success(),
            "{kind}"
        );
        let target = parent.join(".git/refs/heads/main");
        let (send, recv) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            send.send(read("claude-code", &target, &home, &worktree))
                .unwrap();
        });
        let decision = recv
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap_or_else(|_| panic!("{kind} blocked on a named pipe"));
        assert_ne!(decision, "allow", "{kind}");
    }
}

#[test]
fn a_git_file_without_a_matching_backlink_grants_nothing() {
    let (home, parent, worktree) = linked_worktree_fixture();
    std::fs::write(
        parent.join(".git/worktrees/app-feature/gitdir"),
        "/elsewhere/.git\n",
    )
    .unwrap();
    for harness in ["zcode", "claude-code", "omp"] {
        assert_ne!(
            read(
                harness,
                &parent.join(".git/refs/heads/main"),
                &home,
                &worktree
            ),
            "allow",
            "{harness}"
        );
    }
}
