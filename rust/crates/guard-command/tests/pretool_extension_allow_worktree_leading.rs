//! Leading-directory worktree regressions, separated from the core worktree cases.

use super::*;

/// `cd <repository> && git worktree add ... && cd <checkout> && ...`: the
/// setup an agent writes while it is working somewhere else.
///
/// The leading `cd` names a directory and stops, and `&&` carries the add
/// only once it succeeded, so the chain runs in the repository the `cd`
/// names. Every proof after it reads that repository, including the one
/// that places the Git reads in the checkout the add creates.
#[test]
fn a_leading_entry_runs_the_chain_in_the_repository_it_names() {
    let (_cleanup, home, repository) = repository("leading-entry");
    let elsewhere = home.join("org/app-taken");
    let controls = git_github("enabled", &[]);
    let absolute = repository.display().to_string();
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for (cwd, command) in [
            (
                elsewhere.as_path(),
                format!("cd {absolute} && {ADD} && cd ../app-review && git status --short"),
            ),
            (
                elsewhere.as_path(),
                format!("cd ~/org/app && {ADD} && cd ../app-review && git status --short"),
            ),
            (
                elsewhere.as_path(),
                format!(
                    "cd {absolute} && git fetch origin main && {ADD} && cd ../app-review \
                     && git commit --allow-empty -m 'Start review'"
                ),
            ),
            // Each Git step reporting only its last line, the way an agent
            // keeps a long setup readable.
            (
                elsewhere.as_path(),
                format!(
                    "cd {absolute} && git fetch origin main 2>&1 | tail -1 && {ADD} 2>&1 | tail -1 \
                     && cd ../app-review && git status --short"
                ),
            ),
            (
                repository.as_path(),
                format!("cd {absolute} && {ADD} && cd ../app-review && git status --short"),
            ),
            (
                elsewhere.as_path(),
                format!("cd {absolute} && {ADD} && git -C ../app-review status --short"),
            ),
        ] {
            let result = evaluate(&home, cwd, harness, &command, &controls);
            if result.minimum_action != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {}",
                    result.minimum_action, result.reason_code
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A leading `cd` the chain cannot be proved to run after, or that names a
/// directory the proof cannot reach, leaves the steps after it running
/// somewhere no proof looked.
#[test]
fn a_leading_entry_the_proof_cannot_follow_keeps_the_review() {
    let (_cleanup, home, repository) = repository("leading-entry-reviewed");
    let elsewhere = home.join("org/app-taken");
    let controls = git_github("enabled", &[]);
    let absolute = repository.display().to_string();
    for command in [
        // `;` and `||` leave the rest running in the directory the command
        // started in when the `cd` fails.
        format!("cd {absolute}; {ADD} && cd ../app-review && git status --short"),
        format!("cd {absolute} || {ADD} && cd ../app-review && git status --short"),
        // A quoted `~` names a directory called `~`, not home.
        format!("cd '~/org/app' && {ADD} && cd ../app-review && git status --short"),
        // The entry still has to be the checkout the add creates.
        format!("cd {absolute} && {ADD} && cd ../app-other && git status --short"),
        // A step after the entry whose paths the checkout decides.
        format!("cd {absolute} && {ADD} && cd ../app-review && npm run build"),
        // A directory that is not there to enter.
        format!("cd ~/org/app-missing && {ADD} && cd ../app-review && git status --short"),
        // A second entry before the add moves the chain again.
        format!("cd {absolute} && cd .. && {ADD} && cd ../app-review && git status --short"),
    ] {
        let result = evaluate(&home, &elsewhere, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn a_symlinked_leading_entry_never_proves_a_different_checkout() {
    let (_cleanup, home, repository) = repository("leading-entry-symlink");
    let alias = home.join("alias");
    std::os::unix::fs::symlink(&repository, &alias).unwrap();
    let elsewhere = home.join("org/app-taken");
    let controls = git_github("enabled", &[]);
    // Git resolves ../app-review from the physical repo, but the shell's
    // logical PWD follows ~/alias and cd ../app-review enters ~/app-review.
    // It must not inherit proof that examined a different checkout.
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for target in ["~/alias".to_owned(), alias.display().to_string()] {
            let command = format!("cd {target} && {ADD} && cd ../app-review && git status --short");
            let verdict = evaluate(&home, &elsewhere, harness, &command, &controls);
            assert_ne!(
                verdict.minimum_action, "allow",
                "{harness}: {command}: {}",
                verdict.reason_code
            );
        }
    }
}
