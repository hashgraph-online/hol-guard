#![cfg(unix)]

//! A recursive `rm` in the session's Git work tree runs without approval when
//! every target holds only committed, unmodified files. Anything Git could
//! not bring back, ignored files included, keeps the approval.

use crate::pretool_git_session_ops::{git, session, Session};

const PROVEN: &str = "native_exact_safe_recoverable_removal";

fn fixture(label: &str) -> Session {
    let session = session(label);
    let primary = &session.primary;
    std::fs::create_dir_all(primary.join("docs/guide")).unwrap();
    std::fs::write(primary.join("docs/guide/intro.md"), "intro\n").unwrap();
    std::fs::create_dir_all(primary.join("src")).unwrap();
    std::fs::write(primary.join("src/lib.rs"), "fn main() {}\n").unwrap();
    git(&session.home, primary, &["add", "docs", "src"]);
    git(&session.home, primary, &["commit", "--quiet", "-m", "docs"]);
    session
}

/// The command runs without asking: the recoverable-removal proof allows it,
/// or, on macOS, the workspace sandbox already contains a removal of a
/// missing target.
fn unattended(result: &guard_contracts::PreToolResultV1) -> bool {
    let decided = (result.minimum_action.as_str(), result.reason_code.as_str());
    decided == ("allow", PROVEN)
        || (cfg!(target_os = "macos")
            && decided == ("sandbox-required", "native_workspace_containment_required"))
}

fn allowed(session: &Session, command: &str) -> bool {
    unattended(&session.evaluate_at(command, &session.primary))
}

#[test]
fn committed_targets_run_without_approval() {
    let session = fixture("recoverable-allow");
    for command in [
        "rm -rf docs",
        "rm -r docs/guide src",
        "rm -Rfv -- docs",
        "rm --recursive --force docs/guide",
        "rm -rf build",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert!(
            unattended(&result),
            "{command}: {} {}",
            result.minimum_action,
            result.reason_code
        );
    }
    // Committed files are outside the sandbox's proof; only Git's answers.
    for command in ["rm -rf docs", "rm -r docs/guide src"] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", PROVEN),
            "{command}"
        );
    }
    let absolute = format!("rm -rf {}", session.primary.join("docs").display());
    assert!(allowed(&session, &absolute), "{absolute}");
}

#[test]
fn work_git_cannot_restore_keeps_the_approval() {
    let session = fixture("recoverable-keep");
    let primary = &session.primary;
    std::fs::create_dir_all(primary.join("scratch")).unwrap();
    std::fs::write(primary.join("scratch/notes.md"), "draft\n").unwrap();
    std::fs::write(primary.join("src/lib.rs"), "fn main() { edited(); }\n").unwrap();
    std::fs::write(primary.join("docs/guide/new.md"), "new\n").unwrap();
    std::os::unix::fs::symlink(primary.join("docs"), primary.join("docs-link")).unwrap();
    std::fs::write(primary.join("node_modules/pkg/index.js"), "x\n").unwrap();
    std::fs::create_dir_all(primary.join("config")).unwrap();
    std::fs::write(primary.join("config/app.toml"), "a = 1\n").unwrap();
    std::fs::create_dir_all(primary.join("vendor/lib")).unwrap();
    std::fs::write(
        primary.join(".gitignore"),
        "node_modules/\nconfig/.env\nvendor/\n",
    )
    .unwrap();
    for directory in ["assumed", "skipped"] {
        std::fs::create_dir_all(primary.join(directory)).unwrap();
        std::fs::write(primary.join(directory).join("a.txt"), "a\n").unwrap();
        git(&session.home, primary, &["add", directory]);
    }
    git(&session.home, primary, &["add", ".gitignore", "config"]);
    git(&session.home, primary, &["commit", "--quiet", "-m", "more"]);
    std::fs::write(primary.join("config/.env"), "TOKEN=x\n").unwrap();
    git(
        &session.home,
        &primary.join("vendor/lib"),
        &["init", "--quiet", "-b", "main"],
    );
    for (directory, flag) in [
        ("assumed", "--assume-unchanged"),
        ("skipped", "--skip-worktree"),
    ] {
        let file = format!("{directory}/a.txt");
        git(&session.home, primary, &["update-index", flag, &file]);
        std::fs::write(primary.join(&file), "edited\n").unwrap();
    }
    for command in [
        // Untracked, modified and partly untracked trees.
        "rm -rf scratch",
        "rm -rf src",
        "rm -rf docs",
        "rm -rf node_modules scratch",
        // Ignored files, an ignored nested repository and index entries
        // whose working files Git does not compare.
        "rm -rf node_modules",
        "rm -rf ./node_modules/pkg",
        "rm -rf config",
        "rm -rf vendor",
        "rm -rf assumed",
        "rm -rf skipped",
        // The work tree itself, its Git directory and paths outside it.
        "rm -rf .",
        "rm -rf .git",
        "rm -rf ./.GIT/objects",
        "rm -rf ../app-portal-other",
        "rm -rf docs/../scratch",
        // A link answers to its own proof.
        "rm -rf docs-link",
        // Expansions, chains and other programs are not read here.
        "rm -rf node_modules/*",
        "rm -rf $HOME/x",
        "rm -rf ~/x",
        "cd docs && rm -rf guide",
        "rm -rf node_modules && rm -rf docs/guide",
        "rm -rf node_modules; echo done",
        "rm -rf node_modules | cat",
        "sudo rm -rf node_modules",
        "rm -rfi node_modules",
        "rm -rf ':(glob)*'",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(result.reason_code, PROVEN, "{command}");
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
    let outside = format!("rm -rf {}", session.org.join("other").display());
    assert!(!allowed(&session, &outside), "{outside}");
}

#[test]
fn a_session_outside_a_work_tree_keeps_the_approval() {
    let session = fixture("recoverable-outside");
    std::fs::create_dir_all(session.org.join("build")).unwrap();
    let result = session.evaluate_at("rm -rf build", &session.org);
    assert_ne!(result.reason_code, PROVEN);
    assert_ne!(result.minimum_action, "allow");
}

#[test]
fn a_linked_worktree_proves_its_own_tree() {
    let session = fixture("recoverable-worktree");
    let result = session.evaluate_at("rm -rf .gitignore tracked.txt", &session.worktree);
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", PROVEN)
    );
    std::fs::create_dir_all(session.worktree.join("wip")).unwrap();
    std::fs::write(session.worktree.join("wip/a.txt"), "a\n").unwrap();
    let result = session.evaluate_at("rm -rf wip", &session.worktree);
    assert_ne!(result.minimum_action, "allow");
}
