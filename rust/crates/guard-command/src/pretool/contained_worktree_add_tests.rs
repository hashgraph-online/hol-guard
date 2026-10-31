use super::{inside_home_or_temporary, runs_git, split};
use crate::pretool::PathContext;
use std::path::Path;

fn parts(text: &str) -> Option<(String, String, String)> {
    split(text).map(|parts| (parts.add, parts.entered, parts.checks))
}

fn triple(add: &str, entered: &str, checks: &str) -> Option<(String, String, String)> {
    Some((add.to_owned(), entered.to_owned(), checks.to_owned()))
}

#[test]
fn splits_the_add_from_the_checks_it_enters() {
    assert_eq!(
        parts("git worktree add --detach ../app-fix HEAD && cd ../app-fix && bun run build"),
        triple(
            "git worktree add --detach ../app-fix HEAD",
            "cd ../app-fix && bun run build",
            "bun run build",
        )
    );
    assert_eq!(
        parts(concat!(
            "git worktree add -b fix-copy ../app-copy origin/main && cd ../app-copy ",
            "&& cargo test && bun test 2>&1 | tail -5",
        )),
        triple(
            "git worktree add -b fix-copy ../app-copy origin/main",
            "cd ../app-copy && cargo test && bun test 2>&1 | tail -5",
            "cargo test && bun test 2>&1 | tail -5",
        )
    );
    assert_eq!(
        parts("  git worktree add /tmp/app-fix HEAD && cd /tmp/app-fix && npm test\n"),
        triple(
            "git worktree add /tmp/app-fix HEAD",
            "cd /tmp/app-fix && npm test",
            "npm test",
        )
    );
    assert_eq!(
        parts("git -C /tmp/app worktree add /tmp/app-fix && cd /tmp/app-fix && npm test"),
        triple(
            "git -C /tmp/app worktree add /tmp/app-fix",
            "cd /tmp/app-fix && npm test",
            "npm test",
        )
    );
    assert_eq!(
        parts("git worktree add ~/app-fix HEAD && cd ~/app-fix && npm test"),
        triple(
            "git worktree add ~/app-fix HEAD",
            "cd ~/app-fix && npm test",
            "npm test",
        )
    );
}

#[test]
fn leaves_other_shapes_whole() {
    for text in [
        // Nothing to run in the checkout.
        "git worktree add ../app-fix HEAD",
        "git worktree add ../app-fix HEAD && cd ../app-fix",
        "git worktree add ../app-fix HEAD && npm test",
        // The `cd` must name the checkout the add creates.
        "git worktree add ../app-fix HEAD && cd ../app-other && npm test",
        "git worktree add ../app-fix HEAD && cd ../app-fix/ && npm test",
        "git worktree add ../app-fix HEAD && cd ../app-fix ../x && npm test",
        // Only `&&` joins the add, the `cd` and the checks.
        "git worktree add ../app-fix HEAD; cd ../app-fix && npm test",
        "git worktree add ../app-fix HEAD && cd ../app-fix; npm test",
        "git worktree add ../app-fix HEAD || cd ../app-fix && npm test",
        "git worktree add ../app-fix HEAD && cd ../app-fix || npm test",
        "git worktree add ../app-fix HEAD | cat && cd ../app-fix && npm test",
        // Environment prefixes change what the parts mean.
        "GIT_DIR=x git worktree add ../app-fix HEAD && cd ../app-fix && npm test",
        "git worktree add ../app-fix HEAD && cd ../app-fix && CI=1 npm test",
        // A `-C` moves a relative checkout but not the `cd`.
        "git -C ../other worktree add ../app-fix && cd ../app-fix && npm test",
        // A quoted `~` names a literal directory in the `cd`.
        "git worktree add ~/app-fix HEAD && cd '~/app-fix' && npm test",
        // Not a worktree add.
        "git clone https://example.invalid/app ../app-fix && cd ../app-fix && npm test",
        "git worktree list && cd ../app-fix && npm test",
        "mkdir ../app-fix && cd ../app-fix && npm test",
        // Unparsed shapes stay whole.
        "git worktree add ../app-fix HEAD && cd ../app-fix && npm test 'unterminated",
    ] {
        assert_eq!(parts(text), None, "{text}");
    }
}

#[test]
fn git_steps_or_unparsed_checks_count_as_git() {
    for checks in [
        "git commit --allow-empty -m wip",
        "bun run build && git push origin HEAD",
        "npm test; /usr/bin/git status",
    ] {
        assert!(runs_git(checks), "{checks}");
    }
    for checks in ["bun run build", "cargo test && uv run pytest -q", "ls src"] {
        assert!(!runs_git(checks), "{checks}");
    }
}

#[test]
fn only_checkouts_in_home_or_a_temporary_directory_are_served() {
    let home = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let home_text = home.to_str().unwrap();
    let context = PathContext {
        home_dir: Some(home_text),
        ..PathContext::default()
    };
    assert!(inside_home_or_temporary(&home.join("app-build"), context));
    assert!(!inside_home_or_temporary(
        Path::new("/opt/app-build"),
        context
    ));
    assert!(!inside_home_or_temporary(Path::new("/"), context));
}
