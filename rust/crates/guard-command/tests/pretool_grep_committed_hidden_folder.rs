#![cfg(unix)]
//! Recursive `grep` over a folder that holds a committed dot-folder of
//! documents.
//!
//! Design and lint tools commit their own dot-folders to a repository, such as
//! `docs/design/.designtool/design.json`. `grep -rn word docs` went to review
//! because the walk refused every hidden name off its benign list, while
//! `grep -rn word src` beside it was allowed. A hidden entry is now walked when
//! the repository tracks every file it holds and each one is a small document
//! the tracked-file proof finds free of secrets.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Files to write as `(relative path, contents)`.
type Files<'a> = Vec<(&'a str, &'a str)>;

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// A fixture home that owns its tree: the whole root goes away when the
/// guard drops, on a passing test and on a panicking one alike.
struct Home {
    root: PathBuf,
    home: PathBuf,
}

impl std::ops::Deref for Home {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.home
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A home whose `project` repository commits `docs/` with a hidden design
/// folder and a hidden lint file, plus whatever `extra` adds and commits. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home(extra: &[(&str, &str)], untracked: &[(&str, &str)]) -> Home {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-committed-hidden-folder")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let project = root.join("home/project");
    write(project.join("src/main.py"), "print('palette')\n");
    write(project.join("docs/guide.md"), "# Guide\n\nThe palette.\n");
    write(
        project.join("docs/design/.designtool/design.json"),
        "{\"palette\": {\"primary\": \"#1f6feb\"}}\n",
    );
    write(
        project.join("docs/.markdownlint.json"),
        "{\"MD013\": false}\n",
    );
    for (path, text) in extra {
        write(project.join(path), text);
    }
    git(&project, &["init", "--quiet"]);
    git(&project, &["config", "user.name", "Fixture"]);
    git(
        &project,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&project, &["add", "."]);
    git(&project, &["commit", "--quiet", "-m", "Synthetic baseline"]);
    for (path, text) in untracked {
        write(project.join(path), text);
    }
    let home = std::fs::canonicalize(root.join("home")).unwrap();
    Home { root, home }
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    );
    format!("{} / {}", result.minimum_action, result.reason_code)
}

fn allowed(home: &Path, command: &str) -> bool {
    ["zcode", "codex", "claude-code"].iter().all(|harness| {
        let result = action(home, harness, command);
        let allowed = result.starts_with("allow ");
        if !allowed {
            eprintln!("{harness}: {command} => {result}");
        }
        allowed
    })
}

/// Every harness refuses `command`.
fn refused(home: &Path, command: &str) -> bool {
    ["zcode", "codex", "claude-code"].iter().all(|harness| {
        let result = action(home, harness, command);
        let refused = !result.starts_with("allow ");
        if !refused {
            eprintln!("{harness}: {command} => {result}");
        }
        refused
    })
}

#[test]
fn a_committed_hidden_document_folder_does_not_stop_a_search() {
    let home = home(&[], &[]);
    for command in [
        "grep -rn palette docs",
        "grep -rln palette docs/design",
        "grep -rn palette ~/project/docs",
        "grep -rn palette .",
    ] {
        assert!(allowed(&home, command), "{command}");
    }
}

#[test]
fn a_hidden_entry_that_is_not_a_clean_committed_document_keeps_its_review() {
    let key = format!("{{\"aws\": \"{}{}\"}}\n", "AKIA", "IOSFODNN7REALKEY");
    let cases: Vec<(&str, Files, Files)> = vec![
        // A file the repository does not track.
        (
            "untracked",
            vec![],
            vec![("docs/design/.designtool/notes.json", "{}\n")],
        ),
        // A committed file that is not a document.
        (
            "script",
            vec![("docs/design/.designtool/build.sh", "echo palette\n")],
            vec![],
        ),
        // A committed document the detector flags.
        (
            "key",
            vec![("docs/design/.designtool/palette.json", key.as_str())],
            vec![],
        ),
        // Harness folders, credential stores and environment files keep
        // their review even when committed and clean.
        (
            "harness",
            vec![("docs/.claude/notes.md", "palette\n")],
            vec![],
        ),
        // A folder named after a harness holds the agent's own configuration
        // just as the harness folder itself does.
        (
            "harness plugin",
            vec![(
                "docs/.claude-plugin/plugin.json",
                "{\"author\": \"palette\"}\n",
            )],
            vec![],
        ),
        ("store", vec![("docs/.aws/notes.md", "palette\n")], vec![]),
        (
            "environment",
            vec![("docs/.env.example", "PALETTE=blue\n")],
            vec![],
        ),
        (
            "nested store",
            vec![("docs/.designtool/.ssh/notes.md", "palette\n")],
            vec![],
        ),
    ];
    for (label, extra, untracked) in cases {
        let home = home(&extra, &untracked);
        assert!(allowed(&home, "grep -rn palette src"), "{label}: src");
        assert!(
            refused(&home, "grep -rn palette docs"),
            "{label}: grep -rn palette docs"
        );
    }
}

#[test]
fn a_link_inside_a_hidden_folder_keeps_its_review() {
    let home = home(&[], &[]);
    let folder = home.join("project/docs/design/.designtool");
    std::os::unix::fs::symlink(home.join("project/src"), folder.join("source")).unwrap();
    assert!(refused(&home, "grep -rn palette docs"));
    let linked = home.join("project/docs/.linked");
    std::os::unix::fs::symlink(&folder, linked).unwrap();
    std::fs::remove_file(folder.join("source")).unwrap();
    assert!(refused(&home, "grep -rn palette docs"));
}

#[test]
fn a_hidden_folder_with_too_many_entries_keeps_its_review() {
    // Empty folders hold no file, so only a limit that counts folders too
    // stops the walk before it visits all of them.
    let home = home(&[], &[]);
    let folder = home.join("project/docs/design/.designtool");
    for index in 0..40 {
        std::fs::create_dir(folder.join(format!("empty-{index}"))).unwrap();
    }
    assert!(refused(&home, "grep -rn palette docs"));
}
