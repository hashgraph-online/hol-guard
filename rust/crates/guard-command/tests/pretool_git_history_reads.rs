#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

#[test]
fn history_inspections_are_proven_reads() {
    let session = session("history-reads");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            "git blame tracked.txt",
            "git blame -L 1,20 tracked.txt",
            "git blame --line-porcelain tracked.txt",
            "git blame -w -M --date=short tracked.txt | grep fixture",
            "git describe --always",
            "git describe --tags --always",
            "git describe --match 'v*' --dirty=-wip",
            "git reflog",
            "git reflog show main",
            "git reflog -5 --date=iso",
            "git status --short && git describe --always",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            // Running a textconv driver is what the read proof refuses.
            "git blame --textconv tracked.txt",
            "git blame --unknown-option tracked.txt",
            "git reflog expire --all",
            "git reflog delete HEAD@{0}",
            "git describe --unknown-option",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
    // A configured pager runs a program, so the probe keeps the review.
    git(
        &session.home,
        &session.primary,
        &["config", "pager.blame", "./synthetic-never-execute"],
    );
    let result = session.evaluate_at("git blame tracked.txt", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
    // describe prints a ref name, so its own pager key is the one that counts.
    git(
        &session.home,
        &session.primary,
        &["config", "pager.describe", "./synthetic-never-execute"],
    );
    let result = session.evaluate_at("git describe --always", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}

#[test]
fn a_reflog_walk_answers_for_the_signature_configuration_a_log_walk_does() {
    let session = session("history-signatures");
    // The reflog walk is `git log` reading a different ref, so a `%G`
    // placeholder asks it for a signature and runs the verification program.
    let result = session.evaluate_at("git reflog --format=%G?", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
    let result = session.evaluate_at("git reflog", &session.primary);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    git(
        &session.home,
        &session.primary,
        &["config", "log.showSignature", "true"],
    );
    let result = session.evaluate_at("git reflog", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}

#[test]
fn working_tree_reads_answer_for_the_filters_and_monitor_they_would_start() {
    let session = session("history-working-tree");
    for command in [
        "git blame tracked.txt",
        "git describe --dirty",
        "git describe --always",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    // `git blame` turns the working-tree copy into its stored form, and
    // `--dirty` makes `git describe` refresh the index first, so both reach a
    // configured clean filter that a plain `git describe` never runs.
    std::fs::write(
        session.primary.join(".gitattributes"),
        "tracked.txt filter=synthetic\n",
    )
    .unwrap();
    git(
        &session.home,
        &session.primary,
        &[
            "config",
            "filter.synthetic.clean",
            "./synthetic-never-execute",
        ],
    );
    for command in ["git blame tracked.txt", "git describe --dirty"] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    let result = session.evaluate_at("git describe --always", &session.primary);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    git(
        &session.home,
        &session.primary,
        &["config", "--unset", "filter.synthetic.clean"],
    );
    std::fs::remove_file(session.primary.join(".gitattributes")).unwrap();
    // Reading the index the same way can start the file-system monitor.
    git(
        &session.home,
        &session.primary,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    for command in ["git blame tracked.txt", "git describe --broken"] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
