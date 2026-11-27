#![cfg(unix)]
//! A content search over the test files of a project, named by shell globs:
//! `grep -rn "parse_config" tests/*.py tests/**/*.py | head -20`. The tree
//! holds a plugin manifest fixture in a hidden directory. A recursive search
//! of `tests` itself was already allowed, because that file cannot match the
//! pattern and so prints nothing. The glob reads a subset of the same files,
//! so it gets the same clearance.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
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

fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-glob-pattern-clearance")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("home/work/app");
    write(
        repo.join("src/app.py"),
        "def parse_config():\n    return {}\n",
    );
    write(repo.join("src/one.ts"), "export const one = 1;\n");
    write(
        repo.join("tests/test_parse.py"),
        "from app import parse_config\n",
    );
    write(
        repo.join("tests/unit/test_cli.py"),
        "def test_cli():\n    assert True\n",
    );
    // More tests than a glob expansion lists, so the search glob is proven
    // by a walk of `tests`.
    for index in 0..300 {
        write(
            repo.join(format!("tests/test_case_{index}.py")),
            "def test_case():\n    assert True\n",
        );
    }
    // A committed plugin manifest fixture in a hidden directory: a plain
    // walk of `tests` stops at it, a walk under the pattern's clearance reads
    // it.
    write(
        repo.join("tests/fixtures/broken-manifest/.codex-plugin/plugin.json"),
        "{\"name\": \"release_upload\"}\n",
    );
    let root = std::fs::canonicalize(&root).unwrap();
    for arguments in [
        &["init", "-q"][..],
        &["add", "-A"][..],
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ][..],
    ] {
        let status = std::process::Command::new("git")
            .args(arguments)
            .current_dir(root.join("home/work/app"))
            .env("HOME", root.join("home"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
    Fixture {
        home: root.join("home"),
        repo: root.join("home/work/app"),
        root,
    }
}

fn action(fixture: &Fixture, command: &str) -> (String, String) {
    action_in(fixture, &fixture.repo, command)
}

fn action_in(fixture: &Fixture, cwd: &Path, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_glob_over_a_test_tree_gets_the_pattern_clearance_of_its_directory() {
    let fixture = fixture("allowed");
    for command in [
        "grep -rn \"parse_config\" tests 2>/dev/null | head -20",
        "grep -rn \"parse_config\\|load_settings\" tests/*.py tests/**/*.py 2>/dev/null | head -20",
        "grep -n \"parse_config\" tests/**/*.py | head -20",
        "grep -rn parse_config tests/** | head",
        // The same shape over source files.
        "grep -rn \"export const\\|parse_config\" src/*.ts src/**/*.ts 2>/dev/null | head -20",
        "grep -n \"parse_config\" src/**/*.ts* | head -20",
    ] {
        assert_eq!(
            action(&fixture, command),
            ("allow".to_owned(), "native_exact_safe_command".to_owned()),
            "{command}"
        );
    }
}

#[test]
fn a_glob_the_clearance_cannot_cover_keeps_the_review() {
    let fixture = fixture("reviewed");
    for command in [
        // The hidden manifest holds this text, so it could print.
        "grep -rn \"release_upload\" tests/**/*.py | head -20",
        // An inverted match prints the lines that do not match.
        "grep -rnv \"parse_config\" tests/** | head -20",
        "grep -c \"parse_config\" tests/**/*.py",
        // A dot-leading component can reach hidden trees.
        "grep -rn \"parse_config\" tests/.*/*.py | head -20",
    ] {
        let (action, reason) = action(&fixture, command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }

    // A link below the directory can hand the search a file outside it.
    std::os::unix::fs::symlink(fixture.repo.join("src"), fixture.repo.join("tests/linked"))
        .unwrap();
    let command = "grep -rn \"parse_config\" tests/**/*.py | head -20";
    let (action, reason) = action(&fixture, command);
    assert_ne!(action, "allow", "{command}: {reason}");
}

#[test]
fn a_glob_that_must_name_a_directory_needs_a_directory_match() {
    let fixture = fixture("directory");
    // The checkout root holds a file the pattern matches, so a search that
    // falls back to walking the working directory could print it.
    write(fixture.repo.join(".env"), "parse_config=1\n");
    // `tests` holds the files `test_*.py` but no directory of that name, so
    // under `nullglob` these words vanish and `grep -r` walks the checkout.
    for command in [
        "grep -rn \"parse_config\" tests/*.py/ | head -20",
        "grep -rn \"parse_config\" tests/test_*/ | head -20",
        "grep -rn \"parse_config\" tests/*.py/. | head -20",
        // `src` holds no directory, so `**` names `src` itself only under
        // `globstar`.
        "grep -rn \"parse_config\" src/**/. | head -20",
        "grep -rn \"parse_config\" src/**/ | head -20",
    ] {
        let (action, reason) = action(&fixture, command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }
    let command = "grep -rn \"parse_config\" tests/*/ | head -20";
    assert_eq!(
        action(&fixture, command),
        ("allow".to_owned(), "native_exact_safe_command".to_owned()),
        "{command}"
    );
}

#[test]
fn a_glob_that_expands_to_an_option_word_keeps_the_review() {
    let fixture = fixture("option");
    let tests = fixture.repo.join("tests");
    let command = "grep -rn \"parse_config\" * | head -20";
    assert_eq!(
        action_in(&fixture, &tests, command),
        ("allow".to_owned(), "native_exact_safe_command".to_owned()),
        "{command}"
    );
    // A file named `-v` reaches grep as an option, which prints every line
    // the pattern does not match.
    write(tests.join("-v"), "");
    let (action, reason) = action_in(&fixture, &tests, command);
    assert_ne!(action, "allow", "{command}: {reason}");
}

#[test]
fn a_glob_led_by_a_wildcard_that_expands_to_an_option_word_keeps_the_review() {
    let fixture = fixture("option-directory");
    let tests = fixture.repo.join("tests");
    let commands = [
        "grep -rn \"parse_config\" */*.py | head -20",
        "rg -n \"parse_config\" */*.py | head -20",
    ];
    for command in commands {
        assert_eq!(
            action_in(&fixture, &tests, command),
            ("allow".to_owned(), "native_exact_safe_command".to_owned()),
            "{command}"
        );
    }
    // `-ve/a.py` reaches the search as `-v -e /a.py`, which prints every
    // line the pattern does not match.
    write(tests.join("-ve/a.py"), "");
    for command in commands {
        let (action, reason) = action_in(&fixture, &tests, command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }
}
