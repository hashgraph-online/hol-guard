#![cfg(unix)]

//! A repository keeps its sign-in and token code in directories named for it
//! (`src/lib/auth`, `app/api/auth`, `packages/auth`). Listing one, or reading
//! its README or package manifest, is ordinary work and is not held. Data and
//! extensionless files in it, stores named for what they hold, hidden
//! credential folders and a home directory that is itself a work tree keep
//! their review. A held read says what Guard held in words about a read, not
//! about a search.

use std::path::{Path, PathBuf};

use serde_json::json;

use crate::git_helper_fixture::{self as fixture, evaluate_pre_tool_envelope_with_context};

struct Layout {
    root: PathBuf,
    home: PathBuf,
    clone: PathBuf,
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn layout(name: &str) -> Layout {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/feature-directory-read-fixtures")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let home = fixture::canonical_spelling(&root).join("home");
    let clone = home.join("acme-app");
    write(&clone.join(".git/config"), "[core]\n");
    write(&clone.join(".git/HEAD"), "ref: refs/heads/main\n");
    for (relative, text) in [
        ("src/lib/auth/session.ts", "export const a = 1;\n"),
        ("src/lib/auth/README.md", "# Sign-in\n"),
        ("src/lib/auth/config.json", "{\"ttl\": 60}\n"),
        ("src/lib/auth/index", "export {};\n"),
        ("src/lib/auth/oauth_tokens/session.json", "{}\n"),
        ("src/lib/token/issue.ts", "export const t = 1;\n"),
        ("src/lib/secrets/store.md", "notes\n"),
        ("src/lib/plain/README.md", "# Plain\n"),
        ("app/api/auth/email/login/route.ts", "export {};\n"),
        ("packages/auth/package.json", "{\"name\": \"auth\"}\n"),
        ("packages/auth/src/index.ts", "export {};\n"),
        ("playwright/.auth/user.json", "{}\n"),
        (".env", "SESSION_KEY=synthetic\n"),
    ] {
        write(&clone.join(relative), text);
    }
    Layout { root, home, clone }
}

/// The action, reason code and review text of a read of `path` from the clone.
fn read(layout: &Layout, harness: &str, home: &Path, path: &Path) -> (String, String, String) {
    let (tool, key) = if harness == "omp" {
        ("read", "path")
    } else {
        ("Read", "file_path")
    };
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": {key: path}}),
        None,
        None,
        home.to_str(),
        layout.clone.to_str(),
    );
    (result.minimum_action, result.reason_code, result.reason)
}

fn allowed(layout: &Layout, harness: &str, relative: &str) -> bool {
    let (action, code, _) = read(layout, harness, &layout.home, &layout.clone.join(relative));
    action == "allow" && code.starts_with("native_exact_safe_")
}

#[test]
fn feature_directories_and_their_documents_are_read_without_review() {
    let layout = layout("allowed");
    for relative in [
        "src/lib/auth",
        "src/lib/token",
        "app/api/auth",
        "app/api/auth/email",
        "app/api/auth/email/login",
        "packages/auth",
        "packages/auth/src",
    ] {
        assert!(allowed(&layout, "omp", relative), "omp listing {relative}");
    }
    for relative in [
        "src/lib/auth/README.md",
        "packages/auth/package.json",
        "src/lib/auth/session.ts",
        "src/lib/token/issue.ts",
        "app/api/auth/email/login/route.ts",
        "src/lib/plain/README.md",
    ] {
        for harness in ["omp", "claude-code"] {
            assert!(allowed(&layout, harness, relative), "{harness} {relative}");
        }
    }
}

#[test]
fn data_files_stores_and_hidden_credential_folders_keep_their_review() {
    let layout = layout("kept");
    let mut wrongly_allowed = Vec::new();
    for relative in [
        "src/lib/auth/config.json",
        "src/lib/auth/index",
        "src/lib/auth/oauth_tokens",
        "src/lib/auth/oauth_tokens/session.json",
        "src/lib/secrets",
        "src/lib/secrets/store.md",
        "playwright/.auth",
        "playwright/.auth/user.json",
        ".env",
    ] {
        for harness in ["omp", "claude-code"] {
            let (action, _, _) = read(&layout, harness, &layout.home, &layout.clone.join(relative));
            if action == "allow" {
                wrongly_allowed.push(format!("{harness} {relative}"));
            }
        }
    }
    assert!(wrongly_allowed.is_empty(), "{wrongly_allowed:#?}");
}

#[test]
fn a_home_directory_that_is_a_work_tree_keeps_its_review() {
    // A dotfiles repository makes the whole home a repository, so a folder
    // named `auth` inside it is not a project feature.
    let layout = layout("dotfiles");
    write(&layout.home.join(".git/config"), "[core]\n");
    write(&layout.home.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&layout.home.join("auth/README.md"), "# Notes\n");
    for harness in ["omp", "claude-code"] {
        let (action, _, _) = read(
            &layout,
            harness,
            &layout.home,
            &layout.home.join("auth/README.md"),
        );
        assert_ne!(action, "allow", "{harness}");
    }
    let (action, _, _) = read(&layout, "omp", &layout.home, &layout.home.join("auth"));
    assert_ne!(action, "allow");
}

#[test]
fn a_held_read_is_explained_as_a_read_and_not_as_a_search() {
    let layout = layout("wording");
    for relative in [
        "src/lib/auth/config.json",
        "src/lib/auth/index",
        "src/lib/auth/oauth_tokens/session.json",
    ] {
        for harness in ["omp", "claude-code"] {
            let (action, code, reason) =
                read(&layout, harness, &layout.home, &layout.clone.join(relative));
            assert_ne!(action, "allow", "{harness} {relative}");
            if code != "native_file_read_review" {
                continue;
            }
            assert!(
                reason.starts_with("HOL Guard requires review before this file read can execute."),
                "{harness} {relative}: {reason}"
            );
            assert!(reason.contains(relative), "{harness} {relative}: {reason}");
            assert!(!reason.contains("search"), "{harness} {relative}: {reason}");
            // The next step must be one that a later read is not held for again.
            assert!(
                reason.contains("Read a different file, or leave it for the user."),
                "{harness} {relative}: {reason}"
            );
            assert!(
                !reason.contains("inside it"),
                "{harness} {relative}: {reason}"
            );
        }
    }
}

#[test]
fn a_credential_file_read_names_the_file_as_the_reason() {
    let layout = layout("credential");
    let (action, code, reason) = read(&layout, "omp", &layout.home, &layout.clone.join(".env"));
    assert_ne!(action, "allow");
    if code == "native_file_read_review" {
        assert!(reason.contains("credential or secret file"), "{reason}");
        assert!(!reason.contains("SESSION_KEY"), "{reason}");
    }
}
