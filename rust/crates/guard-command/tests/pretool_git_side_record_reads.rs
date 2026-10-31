#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

/// Annotate `HEAD` on the default notes ref and on a selected one, the state
/// an agent finds when it asks what a commit was annotated with.
fn annotate(home: &std::path::Path, repository: &std::path::Path) {
    git(
        home,
        repository,
        &["notes", "add", "-f", "-m", "reviewed", "HEAD"],
    );
    git(
        home,
        repository,
        &[
            "notes", "--ref", "build", "add", "-f", "-m", "built", "HEAD",
        ],
    );
}

#[test]
fn printing_note_and_bisect_forms_are_proven_reads() {
    let session = session("side-record-reads");
    for cwd in [&session.primary, &session.worktree] {
        annotate(&session.home, cwd);
        for command in [
            "git bisect log",
            "git notes",
            "git notes list",
            "git notes list HEAD",
            "git notes show",
            "git notes show HEAD",
            "git notes show HEAD~0",
            // `--ref` is an option of `git notes`, ahead of the subcommand.
            "git notes --ref build",
            "git notes --ref build list",
            "git notes --ref=build list HEAD",
            "git notes --ref build show",
            "git notes --ref=build show HEAD",
            "git notes list | head -3",
            "git notes list && git status --short && git log --oneline -3",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            // Every spelling that writes the notes ref, moves a ref or runs
            // a program is judged by the rules that already cover it.
            "git notes add -m fix HEAD",
            "git notes --ref build add -m fix HEAD",
            "git notes edit HEAD",
            "git notes remove HEAD",
            "git notes prune",
            "git bisect start HEAD HEAD~1",
            "git bisect run ./flaky.sh",
            // Git refuses `--ref` after the subcommand, so it is not read.
            "git notes list --ref build",
            "git notes show --ref build HEAD",
            "git notes show HEAD extra",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
}

#[test]
fn a_configured_notes_pager_keeps_every_printing_form_reviewed() {
    let session = session("notes-pager");
    annotate(&session.home, &session.primary);
    let result = session.evaluate_at("git notes show HEAD", &session.primary);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    git(
        &session.home,
        &session.primary,
        &["config", "pager.notes", "./synthetic-never-execute"],
    );
    for command in [
        "git notes list",
        "git notes show HEAD",
        "git notes --ref build show HEAD",
        "git log -1 && git notes list",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// `git notes show` execs `git show <note>`, so a program configured under
/// `pager.show` starts for it, and for no other notes form.
#[test]
fn a_configured_show_pager_keeps_only_the_note_show_reviewed() {
    let session = session("notes-show-pager");
    annotate(&session.home, &session.primary);
    git(
        &session.home,
        &session.primary,
        &["config", "pager.show", "./synthetic-never-execute"],
    );
    for command in [
        "git notes show",
        "git notes show HEAD",
        "git notes --ref build show HEAD",
        "git log -1 && git notes show HEAD",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in ["git notes", "git notes list", "git notes --ref build list"] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A notes tree names whatever object it was built with, so the note `git
/// notes show` execs `git show` on can be a commit, rendered with the patch,
/// diff driver and signature settings of `git show`. Each setting keeps the
/// show form reviewed and leaves the listing, which prints no patch, alone.
#[test]
fn a_render_setting_keeps_only_the_note_show_reviewed() {
    for (index, (key, value)) in [
        ("diff.synthetic.textconv", "./synthetic-never-execute"),
        ("diff.external", "./synthetic-never-execute"),
        ("diff.synthetic.command", "./synthetic-never-execute"),
        ("log.showSignature", "true"),
    ]
    .into_iter()
    .enumerate()
    {
        let session = session(&format!("notes-render-{index}"));
        annotate(&session.home, &session.primary);
        git(&session.home, &session.primary, &["config", key, value]);
        for command in ["git notes show HEAD", "git notes --ref build show HEAD"] {
            let result = session.evaluate_at(command, &session.primary);
            assert_ne!(
                result.minimum_action, "allow",
                "{key}: {command}: {}",
                result.reason_code
            );
        }
        for command in ["git notes list", "git notes --ref build list"] {
            let result = session.evaluate_at(command, &session.primary);
            assert_eq!(
                result.minimum_action, "allow",
                "{key}: {command}: {}",
                result.reason_code
            );
        }
    }
}

/// `git bisect log` copies `.git/BISECT_LOG` out through `open`, which follows
/// a link, so a log that is a link keeps the review while a plain record and
/// a session with no record stay reads.
#[test]
fn a_linked_bisect_log_keeps_the_review() {
    let session = session("bisect-log-link");
    let log = session.primary.join(".git").join("BISECT_LOG");
    let outside = session.home.join("synthetic-outside-record");
    std::fs::write(&outside, "synthetic\n").unwrap();
    for (label, linked) in [
        ("missing", None),
        ("plain", Some(false)),
        ("linked", Some(true)),
    ] {
        let _ = std::fs::remove_file(&log);
        match linked {
            None => {}
            Some(false) => std::fs::write(&log, "git bisect start\n").unwrap(),
            Some(true) => std::os::unix::fs::symlink(&outside, &log).unwrap(),
        }
        let result = session.evaluate_at("git bisect log", &session.primary);
        assert_eq!(
            result.minimum_action == "allow",
            linked != Some(true),
            "{label}: {}",
            result.reason_code
        );
    }
}
