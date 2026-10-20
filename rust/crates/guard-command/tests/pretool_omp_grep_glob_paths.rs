#![cfg(unix)]
//! An Oh My Pi `grep` whose `path` holds a glob searches only files below
//! the folder before the glob. It is allowed when a search of that whole
//! folder would be, with no ignore file narrowing it and no link below it
//! leading out. A sensitive file anywhere below the folder, a link that
//! leaves it, or a selector that could climb out of it keeps review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A project with TypeScript sources and docs, in a home that also holds a
/// key, a `.env` folder and a clean folder. The root stays below the target
/// directory: `$TMPDIR` on macOS resolves under `/private/var`, which the
/// sensitive-root screen rejects.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-grep-glob-paths")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    for file in [
        "project/src/index.ts",
        "project/src/lib/util.ts",
        "project/docs/guide.md",
        ".ssh/id_rsa",
        "secret-dir/.env",
        "clean/a.txt",
    ] {
        write(home.join(file), "synthetic fixture\n");
    }
    Fixture {
        root,
        home,
        project,
    }
}

fn grep(fixture: &Fixture, path: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        // The pattern matches every fixture file, so no sensitive file is
        // cleared by what it cannot print.
        &json!({"tool_name": "grep", "tool_input": {"pattern": "fixture", "path": path}}),
        None,
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn a_glob_below_a_clean_folder_is_allowed() {
    let f = fixture("clean");
    for path in [
        "src/**/*.ts",
        "src/*.ts",
        "src/lib/????.ts",
        "**/*.ts",
        "docs/*.md; src/**/*.ts",
        "src/index.ts; src/lib/*.ts",
    ] {
        let result = grep(&f, path);
        assert!(allowed(&result), "{path}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_bounded_search_scope", "{path}");
    }
}

#[test]
fn a_sensitive_file_below_the_folder_keeps_review_even_when_ignored() {
    let f = fixture("env");
    write(f.project.join("src/.env"), "synthetic fixture\n");
    // An ignore file does not narrow the proof: a glob may select what it
    // excludes.
    write(f.project.join("src/.gitignore"), ".env\n");
    for path in ["src/**/*.ts", "src/*.ts", "**/*.md", "docs/*.md; src/*.ts"] {
        assert!(!allowed(&grep(&f, path)), "{path}");
    }
    assert!(allowed(&grep(&f, "docs/*.md")));
}

#[test]
fn a_link_out_of_the_folder_keeps_review() {
    let f = fixture("links");
    // Even a link to a folder with no sensitive file leaves what the walk
    // proved.
    std::os::unix::fs::symlink(f.home.join("clean"), f.project.join("src/vendor")).unwrap();
    std::os::unix::fs::symlink(f.home.join(".ssh/id_rsa"), f.project.join("docs/key")).unwrap();
    std::os::unix::fs::symlink(f.project.join("src"), f.project.join("linked")).unwrap();
    for path in [
        "src/**/*.ts",
        "src/*.ts",
        "docs/*",
        "linked/*.ts",
        "**/*.ts",
    ] {
        assert!(!allowed(&grep(&f, path)), "{path}");
    }
}

#[test]
fn a_git_link_out_of_the_folder_keeps_review() {
    let f = fixture("git-link");
    // A `.git` link is still a link: the names walk skips only a real one.
    std::os::unix::fs::symlink(f.home.join("clean"), f.project.join("src/.git")).unwrap();
    for path in ["src/**/*.ts", "src/*.ts", "**/*.ts"] {
        assert!(!allowed(&grep(&f, path)), "{path}");
    }
    assert!(allowed(&grep(&f, "docs/*.md")));
}

#[test]
fn a_selector_that_could_leave_the_folder_keeps_review() {
    let f = fixture("escape");
    for path in [
        "src/**/../../../.ssh/*",
        "src/*/../../../secret-dir/*",
        "../project/src/*.ts",
        "../../home/.ssh/*",
        "~/.ss*/*",
        "~/*/.env",
        "{src,docs}/*.ts",
        "src/{lib,../../.ssh}/*",
        "src/[.][.]/*",
        "src/\\*.ts",
        "/etc/*",
        "src/$HOME/*",
    ] {
        assert!(!allowed(&grep(&f, path)), "{path}");
    }
}
