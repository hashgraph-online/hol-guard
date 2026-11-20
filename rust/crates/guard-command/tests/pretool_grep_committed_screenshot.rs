#![cfg(unix)]
//! Recursive `grep` over a tree that holds a screenshot of ordinary size.
//!
//! A project commits screenshots of the screens it documents, and they are
//! named for the screen: `docs/screens/auth-desktop-login.png`. The
//! credential-name screen reads that `auth` prefix as credential material, so
//! the walk had to prove the file before it would clear the search. It proved
//! it as a text fixture, against a budget of a quarter megabyte per file, and
//! a full-window capture runs several megabytes past that. Every recursive
//! search over such a tree was reviewed. An image is now proven as an image,
//! against a budget of its own.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn write(path: PathBuf, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
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

/// A PNG of `chunks`, closed by `IEND`, with the CRC of each chunk.
fn png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let end: (&[u8; 4], &[u8]) = (b"IEND", b"");
    for (kind, data) in chunks.iter().chain([&end]) {
        bytes.extend_from_slice(&(u32::try_from(data.len()).unwrap()).to_be_bytes());
        bytes.extend_from_slice(*kind);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&crc32(kind, data).to_be_bytes());
    }
    bytes
}

/// The CRC-32 a PNG chunk carries, over its type and its data.
fn crc32(kind: &[u8; 4], data: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in kind.iter().chain(data) {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0xEDB8_8320
            } else {
                value >> 1
            };
        }
    }
    !value
}

/// A capture the size screenshots are, built rather than embedded: the walk
/// reads the chunk layout and scans the bytes for text, and neither depends
/// on what the pixels show.
fn capture(pixel_bytes: usize) -> Vec<u8> {
    png(&[
        (b"IHDR", &[0, 0, 11, 72, 0, 0, 7, 128, 8, 6, 0, 0, 0]),
        (b"pHYs", &[0, 0, 22, 37, 0, 0, 22, 37, 1]),
        (b"IDAT", &vec![0u8; pixel_bytes]),
    ])
}

/// A fixture home that owns its tree.
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

/// A home whose `project` repository documents two screens and commits a
/// capture of `pixel_bytes` for each. The root stays below the target
/// directory: `$TMPDIR` on macOS resolves under `/private/var`, which the
/// sensitive-root screen rejects.
fn home(pixel_bytes: usize) -> Home {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-committed-screenshot")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let project = root.join("home/project");
    write(project.join("src/main.py"), b"print('login')\n");
    write(
        project.join("docs/guide.md"),
        b"# Guide\n\nThe login screen.\n",
    );
    write(
        project.join("docs/screens/auth-desktop-login.png"),
        &capture(pixel_bytes),
    );
    write(
        project.join("docs/screens/auth-desktop-policy-review.png"),
        &capture(pixel_bytes),
    );
    git(&project, &["init", "--quiet"]);
    git(&project, &["config", "user.name", "Fixture"]);
    git(
        &project,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&project, &["add", "."]);
    git(&project, &["commit", "--quiet", "-m", "Synthetic baseline"]);
    let home = std::fs::canonicalize(root.join("home")).unwrap();
    Home { root, home }
}

/// The harness whose agent chooses a search tool by name and walks the tree
/// it is given. Claude Code reviews a search rooted on the project directory
/// itself for reasons of its own, which this fixture is not about.
const SEARCH: &[&str] = &["omp"];

/// The harnesses that run a recursive search as a shell command.
const SHELL: &[&str] = &["omp", "codex", "claude-code"];

fn action(home: &Path, harness: &str, tool: &str, tool_input: serde_json::Value) -> String {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": tool_input}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    );
    format!("{} / {}", result.minimum_action, result.reason_code)
}

/// Whether every harness in `harnesses` allows `tool` over its input.
fn allowed(home: &Path, harnesses: &[&str], tool: &str, tool_input: serde_json::Value) -> bool {
    harnesses.iter().all(|harness| {
        let result = action(home, harness, tool, tool_input.clone());
        let allowed = result.starts_with("allow ");
        if !allowed {
            eprintln!("{harness}: {tool} {tool_input} => {result}");
        }
        allowed
    })
}

#[test]
fn a_search_tool_walks_past_captures_of_ordinary_size() {
    // Three megabytes each is an unremarkable full-window retina capture and
    // larger than the whole budget a walk has for the documents it reads.
    let home = home(3 * 1024 * 1024);
    let project = home.join("project");
    let tree = project.to_str().unwrap();
    assert!(allowed(
        &home,
        SEARCH,
        "grep",
        json!({"pattern": "login", "path": tree})
    ));
    assert!(allowed(
        &home,
        SEARCH,
        "grep",
        json!({"pattern": "login", "path": project.join("docs").to_str().unwrap()})
    ));
    assert!(allowed(
        &home,
        SEARCH,
        "glob",
        json!({"pattern": "**/*.md", "path": tree})
    ));
}

#[test]
fn a_shell_search_walks_past_captures_of_ordinary_size() {
    let home = home(3 * 1024 * 1024);
    for command in ["grep -rn login docs", "grep -rln login docs/screens"] {
        assert!(
            allowed(&home, SHELL, "bash", json!({"command": command})),
            "{command}"
        );
    }
}

#[test]
fn a_capture_past_the_image_budget_keeps_its_review() {
    // Nine megabytes is past what one image may spend, so the walk cannot
    // say what the file holds and the search keeps the review it had.
    let home = home(9 * 1024 * 1024);
    let tree = home.join("project");
    assert!(
        !allowed(
            &home,
            SEARCH,
            "grep",
            json!({"pattern": "login", "path": tree.to_str().unwrap()})
        ),
        "a capture past the budget was proven"
    );
}
