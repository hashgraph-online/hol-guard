#![cfg(unix)]
//! A `for` loop over a glob that labels each file it prints, or prints it only
//! when a test holds:
//!
//! `for f in docs/release-*.md; do [ -f "$f" ] && { printf '%s\n' "### $f"; sed -n '1,120p' "$f"; }; done`
//!
//! The loop proof writes the body out once per pattern and lets the ordinary
//! proofs read it. Two shapes kept such a loop in review: a `{ …; }` group,
//! which the body grammar did not read, and a reference inside a larger
//! quoted word, `"### $f"`, which the proof refused because a glued
//! reference spells a different pattern when written out. An `echo` or a
//! `printf` with a single-quoted format only prints that word, so the label
//! is the same work whichever name it holds. Reads, redirections and pipes
//! keep the old rule.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn action(harness: &str, command: &str, home: &Path, cwd: &Path) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
    .minimum_action
}

fn fixture() -> PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/loop-labels-and-groups")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/app/docs", "work/app/keys", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (file, text) in [
        ("work/app/docs/release-1.md", "# one\n"),
        ("work/app/docs/release-2.md", "# two\n"),
        ("work/app/keys/README.md", "keys\n"),
        ("work/app/keys/deploy.pem", "synthetic\n"),
        (".ssh/id_ed25519", "synthetic\n"),
    ] {
        std::fs::write(root.join(file), text).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    let status = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(root.join("work/app"))
        .env("HOME", &root)
        .status()
        .unwrap();
    assert!(status.success());
    root
}

const HARNESSES: [&str; 3] = ["claude-code", "codex", "omp"];

#[test]
fn a_loop_that_labels_or_groups_its_reads_is_allowed() {
    let home = fixture();
    let app = home.join("work/app");
    for harness in HARNESSES {
        for command in [
            "for f in docs/release-*.md; do [ -f \"$f\" ] && { printf '%s\\n' \"### $f\"; sed -n '1,120p' \"$f\"; }; done",
            "for f in docs/release-*.md; do echo \"### $f\"; cat \"$f\"; done",
            "for f in docs/release-*.md; do { echo; echo \"== $f ==\"; head -20 \"$f\"; }; done",
            "for f in docs/*.md; do { cat \"$f\"; }; done",
            "for f in docs/release-*.md; do printf '\\n## %s\\n' \"file $f\"; cat \"$f\"; done",
        ] {
            assert_eq!(
                action(harness, command, &home, &app),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_labelled_or_grouped_loop_keeps_the_review_of_what_it_does() {
    let home = fixture();
    let app = home.join("work/app");
    for harness in HARNESSES {
        for command in [
            // The pattern matches a key; the group reads every match.
            "for f in keys/*; do { echo \"### $f\"; cat \"$f\"; }; done",
            // A group may read something the loop never names.
            "for f in docs/*.md; do { cat \"$f\"; cat ~/.ssh/id_ed25519; }; done",
            // The label goes to a file or a shell, not to the terminal.
            "for f in docs/*.md; do echo \"### $f\" > \"$f.bak\"; done",
            "for f in docs/*.md; do echo \"cat $f\" | sh; done",
            // A format the name can reach is not a plain label.
            "for f in docs/*.md; do printf \"$f %s\\n\" x; done",
            // A glued reference that is read keeps its review.
            "for f in docs/*.md; do { cat \"bak-$f\"; }; done",
            // `cd` inside the group moves the rest of the loop.
            "for f in docs/*.md; do { cd ~/.ssh; cat id_ed25519; }; done",
            // A body that never reads the loop variable is proved as one
            // pass, but a `cd` inside a group runs on every pass: two passes
            // climb from the checkout to the home folder, whose hidden
            // entries `ls -a` then lists, as `cd ..; cd ..; ls -a` would.
            "for i in 1 2; do { cd ..; }; ls -a; done",
            "for i in 1 2; do { cd ..; ls; }; done; ls -a",
            "ls && for i in 1 2; do { cd ..; }; done && ls -a",
        ] {
            assert_ne!(
                action(harness, command, &home, &app),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
