#![cfg(unix)]

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn evaluate(home: &Path, cwd: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn git(home: &Path, repository: &Path, arguments: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

/// `org/app` below a fresh home, with a remote-tracking `origin/main`, a
/// sibling repository and a symlink beside it that leads out of `org` into a
/// directory every user can write, where no checkout is admitted.
fn repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-{name}-{unique}"));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let organization = home.join("org");
    let repository = organization.join("app");
    for path in [&root, &home, &organization, &repository] {
        directory(path);
    }
    git(
        &home,
        &repository,
        &["init", "--quiet", "--initial-branch=main"],
    );
    git(
        &home,
        &repository,
        &["config", "user.name", "Guard Fixture"],
    );
    git(
        &home,
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    git(&home, &repository, &["add", "tracked.txt"]);
    git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    let sibling = organization.join("service");
    directory(&sibling);
    git(&home, &sibling, &["init", "--quiet"]);
    directory(&root.join("elsewhere"));
    std::fs::set_permissions(
        root.join("elsewhere"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("elsewhere"), organization.join("link")).unwrap();
    (cleanup, home, repository)
}

fn assert_allowed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

fn assert_reviewed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_ne!(result.minimum_action, "allow", "{command}");
}

/// Without `-b` Git checks the reference out detached and creates no branch,
/// except with no reference at all, where it names a branch after the
/// destination and starts it at `HEAD`.
#[test]
fn detached_worktree_add_needs_a_reference() {
    let (_cleanup, home, repository) = repository("detached");
    for command in [
        "git worktree add ../app-review origin/main",
        "git worktree add ../app-review refs/heads/main",
        "git worktree add --detach ../app-review origin/main",
        // Git names the new branch after the directory and starts it at HEAD.
        "git worktree add ../app-review",
    ] {
        assert_allowed(&home, &repository, command);
    }
    for command in [
        "git worktree add -b review --detach ../app-review origin/main",
        "git worktree add ../service origin/main",
        "git worktree add ../link/review origin/main",
        "git worktree add ../app-review origin/main~1",
    ] {
        assert_reviewed(&home, &repository, command);
    }
}

/// The implied branch is only HEAD's tree while no branch of that name exists
/// and `worktree.guessRemote` is off; either would check out something the
/// proof never read.
#[test]
fn an_implied_branch_name_must_be_free_and_unguessed() {
    let (_cleanup, home, repository) = repository("implied");
    let command = "git worktree add ../app-review";
    assert_allowed(&home, &repository, command);
    git(&home, &repository, &["branch", "app-review"]);
    assert_reviewed(&home, &repository, command);
    git(&home, &repository, &["branch", "--delete", "app-review"]);
    assert_allowed(&home, &repository, command);
    git(
        &home,
        &repository,
        &["config", "worktree.guessRemote", "true"],
    );
    assert_reviewed(&home, &repository, command);
}

/// Reads in the checkout the command itself creates share the repository's
/// proven configuration.
#[test]
fn reads_in_the_new_worktree_are_allowed() {
    let (_cleanup, home, repository) = repository("chain");
    for command in [
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git log --oneline -3 && git status",
        "git worktree add ../app-flat origin/main && cd ../app-flat && git status --short",
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git log --oneline | head -5",
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat; git diff --stat",
    ] {
        assert_allowed(&home, &repository, command);
    }
}

/// Writes, pushes, other directories and paths outside the checkout keep
/// their review.
#[test]
fn other_work_in_the_new_worktree_stays_reviewed() {
    let (_cleanup, home, repository) = repository("chain-reviewed");
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        "cd ../app-flat && git commit --allow-empty -m wip",
        "cd ../app-flat && git push origin flat",
        "cd ../app-flat && git config core.hooksPath hooks",
        "cd ../app-flat && git -c core.fsmonitor=true status",
        "cd ../app-flat && git -C ../service status",
        "cd ../app-flat && git log -- ../service",
        "cd ../app-flat && git diff --no-index tracked.txt other.txt",
        "cd ../app-flat && ls",
        "cd ../app-flat && git status || git push origin flat",
        "cd ../app-flat && git status & git status",
        "cd ../service && git status && git commit --allow-empty -m wip",
        "cd .. && git status",
        "cd ../app-flat/.. && git status",
    ] {
        assert_reviewed(&home, &repository, &format!("{add} && {tail}"));
    }
    for command in [
        "git worktree add -b flat ../service origin/main && cd ../service && git status",
        "git worktree add -b flat ../link/flat origin/main && cd ../link/flat && git status",
        "git worktree add -b flat ../app-flat origin/main; cd ../app-flat && git status",
        "git worktree add -b flat ../app-flat origin/main && git status && cd ../app-flat",
        "rm -rf ../app-flat && git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git status",
    ] {
        assert_reviewed(&home, &repository, command);
    }
}

/// With `git -C`, a failed `cd` leaves the shell in a directory the proof
/// never read, so a read after `;` stays reviewed.
#[test]
fn fallback_reads_after_a_routed_add_stay_reviewed() {
    let (_cleanup, home, repository) = repository("chain-routed");
    let organization = repository.parent().unwrap();
    let destination = organization.join("app-flat");
    let (repository_text, destination) = (repository.display(), destination.display());
    assert_reviewed(
        &home,
        organization,
        &format!(
            "git -C {repository_text} worktree add -b flat {destination} origin/main && cd {destination}; git log --oneline -3"
        ),
    );
}

/// `git -C <checkout>` names the new checkout without a `cd`, in any
/// spelling that resolves to it. A `mkdir` may run in the shell's own
/// directory between the reads.
#[test]
fn routed_reads_in_the_new_worktree_are_allowed() {
    let (_cleanup, home, repository) = repository("chain-dash-c");
    let destination = repository.parent().unwrap().join("app-flat");
    let destination = destination.display();
    for command in [
        "git worktree add -b flat ../app-flat origin/main && git -C ../app-flat status --short".to_owned(),
        "git worktree add -b flat ../app-flat origin/main && git -C ../app-flat log --oneline | head -5".to_owned(),
        "git worktree add -b flat ~/org/app-flat origin/main && git -C ~/org/app-flat status --short".to_owned(),
        format!("git worktree add -b flat {destination} origin/main && git --no-pager -C {destination} log --oneline -3 && git -C ../app-flat status"),
        "git worktree add -b flat ~/org/app-flat origin/main && mkdir -p ~/notes && git -C ~/org/app-flat status --short".to_owned(),
    ] {
        assert_allowed(&home, &repository, &command);
    }
}

/// Reads routed anywhere but the new checkout, writes, a `;` that would run
/// the read after a failed add, and anything else between the reads keep
/// their review, as does a `mkdir` in or below the new checkout, which
/// could follow a link the checkout brings.
#[test]
fn other_routed_work_after_a_worktree_add_stays_reviewed() {
    let (_cleanup, home, repository) = repository("chain-dash-c-reviewed");
    // A link made before the add that will lead into the new checkout.
    std::os::unix::fs::symlink(
        repository.parent().unwrap().join("app-flat"),
        home.join("pending"),
    )
    .unwrap();
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        "&& git -C .. status",
        "&& git -C ../app-flat/.. status",
        "&& git -C ../link/../app-flat status",
        "&& git -C '~/org/app-flat' status",
        "&& git -C ../app-flat commit --allow-empty -m wip",
        "&& git -C ../app-flat push origin flat",
        "&& git -C ../app-flat -c core.fsmonitor=true status",
        "&& git -C ../app-flat -C ../service status",
        "&& git -C ../app-flat log -- ../service",
        "&& git -C ../app-flat status && git status",
        "&& git -C ../app-flat status && ls",
        "&& touch ../app-flat/.gitattributes && git -C ../app-flat status",
        "; git -C ../app-flat status",
        "|| git -C ../app-flat status",
        "&& mkdir -p ../app-flat/notes && git -C ../app-flat status",
        "&& mkdir -p ~/org/app-flat/notes/keys && git -C ../app-flat status",
        "&& mkdir -p ~/pending/notes && git -C ../app-flat status",
        "&& mkdir -p ~/.ssh/keys && git -C ../app-flat status",
    ] {
        assert_reviewed(&home, &repository, &format!("{add} {tail}"));
    }
    assert_reviewed(
        &home,
        &repository,
        "git worktree add -b flat ../link/flat origin/main && git -C ../link/flat status",
    );
}

/// Without `-b` or `--detach`, `git worktree add <path> <branch>` checks an
/// existing local branch out into the new checkout, running the same
/// checkout as the `-b` form. The proof reads that branch's tip.
#[test]
fn existing_branch_worktree_add_is_allowed() {
    let (_cleanup, home, repository) = repository("existing-branch");
    git(&home, &repository, &["branch", "feat/discovery-fix"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/tags/release-lane", "HEAD"],
    );
    let organization = repository.parent().unwrap().display().to_string();
    for command in [
        "git worktree add ../app-discovery-fix feat/discovery-fix".to_owned(),
        "git worktree add ../app-discovery-fix feat/discovery-fix 2>&1 | tail -2".to_owned(),
        "git worktree add --quiet ../app-discovery-fix feat/discovery-fix".to_owned(),
        format!("git worktree add {organization}/app-discovery-fix feat/discovery-fix"),
        "git worktree add ../app-discovery-fix feat/discovery-fix && cd ../app-discovery-fix && git log --oneline -3".to_owned(),
        // No branch of that name: Git detaches at the tag.
        "git worktree add ../app-release release-lane".to_owned(),
        // A new branch, or a detached checkout, starting from a bare name.
        "git worktree add -b review ../app-review main".to_owned(),
        "git worktree add -b review ../app-review feat/discovery-fix".to_owned(),
        "git worktree add --detach ../app-review feat/discovery-fix".to_owned(),
        "git worktree add -b review ../app-review release-lane".to_owned(),
        format!("git worktree add -b review {organization}/app-review main"),
    ] {
        assert_allowed(&home, &repository, &command);
    }
}

/// Force-resets, forced checkouts, routed or reconfigured Git, other
/// destinations and names that resolve to nothing keep their review.
#[test]
fn existing_branch_worktree_add_neighbours_stay_reviewed() {
    let (_cleanup, home, repository) = repository("existing-branch-reviewed");
    git(&home, &repository, &["branch", "feat/discovery-fix"]);
    for command in [
        "git worktree add -B feat/discovery-fix ../app-discovery-fix origin/main",
        "git worktree add -f ../app-discovery-fix feat/discovery-fix",
        "git worktree add --force ../app-discovery-fix feat/discovery-fix",
        "git worktree add ../app-discovery-fix feat/discovery-fix~1",
        "git worktree add -b other ../app-discovery-fix feat/discovery-fix~1",
        "git worktree add -b other ../app-discovery-fix missing-branch",
        "git worktree add --detach ../app-discovery-fix missing-branch",
        "git -c core.hooksPath=hooks worktree add ../app-discovery-fix feat/discovery-fix",
        "GIT_DIR=../service/.git git worktree add ../app-discovery-fix feat/discovery-fix",
        "git worktree add ../service feat/discovery-fix",
        "git worktree add ../link/review feat/discovery-fix",
        "git worktree add ../.app-discovery-fix feat/discovery-fix",
        "git worktree add ../app-discovery-fix feat/discovery-fix && cd ../app-discovery-fix && git commit --allow-empty -m wip",
    ] {
        assert_reviewed(&home, &repository, command);
    }
    // A post-checkout hook runs in the new checkout.
    let hook = repository.join(".git/hooks/post-checkout");
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_reviewed(
        &home,
        &repository,
        "git worktree add ../app-discovery-fix feat/discovery-fix",
    );
}

/// An unquoted `~/` destination is the shell's HOME, here the declared one,
/// so it names the same checkout as the absolute spelling. Quoted, Git would
/// create a literal `~` directory, and other users' homes, hidden leaves,
/// existing paths and a symlinked parent leading somewhere unowned stay
/// reviewed as before.
#[test]
fn home_relative_worktree_destinations_match_the_absolute_spelling() {
    let (_cleanup, home, repository) = repository("home-relative");
    git(&home, &repository, &["branch", "feat/discovery-fix"]);
    for command in [
        "git worktree add ~/app-discovery-fix feat/discovery-fix",
        "git worktree add ~/org/app-discovery-fix feat/discovery-fix 2>&1 | tail -2",
        "git worktree add -b fix/home-lane ~/org/app-home-lane origin/main",
    ] {
        assert_allowed(&home, &repository, command);
    }
    for command in [
        "git worktree add '~/app-discovery-fix' feat/discovery-fix",
        "git worktree add \"~/app-discovery-fix\" feat/discovery-fix",
        "git worktree add ~root/app-discovery-fix feat/discovery-fix",
        "git worktree add ~ feat/discovery-fix",
        "git worktree add ~/.app-discovery-fix feat/discovery-fix",
        "git worktree add ~/org/service feat/discovery-fix",
        "git worktree add ~/org/link/review feat/discovery-fix",
        "git worktree add ~/org/app/.github/workflows/fix feat/discovery-fix",
        "HOME=/tmp git worktree add ~/app-discovery-fix feat/discovery-fix",
    ] {
        assert_reviewed(&home, &repository, command);
    }
}

/// A `cd` spelled through a fixed symlinked parent, as `/tmp` is on macOS,
/// enters the checkout Git creates at the physical path.
#[test]
fn cd_through_a_symlinked_temporary_parent_matches_the_checkout() {
    let (_cleanup, home, repository) = repository("tmp-spelling");
    let spelled_home = Path::new("/tmp")
        .join(home.parent().unwrap().file_name().unwrap())
        .join("home");
    let leaf = format!("/tmp/guard-worktree-leaf-{}", std::process::id());
    let in_home = spelled_home.join("app-tmp").display().to_string();
    for command in [
        format!("git worktree add --detach {in_home} origin/main && cd {in_home} && git log -1 --format='%H %s'"),
        format!(
            "git -C {} worktree add -q --detach {leaf} HEAD && cd {leaf} && git log -1 --format='%H %s'",
            repository.display()
        ),
    ] {
        assert_allowed(&home, &repository, &command);
    }
    assert_reviewed(
        &home,
        &repository,
        &format!("git worktree add --detach {in_home} origin/main && cd {leaf} && git log -1"),
    );
}

/// A `cd` through a link someone else could swap before it runs, or a
/// destination through a fixed link that leads on through such a link,
/// stays reviewed: the read could land where the proof never looked.
#[test]
fn swappable_links_on_the_way_to_the_checkout_stay_reviewed() {
    let (_cleanup, home, repository) = repository("swappable-link");
    let organization = repository.parent().unwrap();
    // `elsewhere` is writable by every user without the sticky bit, so
    // anyone could repoint a link in it.
    let swappable = home.parent().unwrap().join("elsewhere").join("org");
    std::os::unix::fs::symlink(organization, &swappable).unwrap();
    std::os::unix::fs::symlink(&swappable, home.join("via")).unwrap();
    let destination = organization.join("app-flat").display().to_string();
    let add = format!("git worktree add -b flat {destination} origin/main");
    assert_allowed(
        &home,
        &repository,
        &format!("{add} && cd {destination} && git log -1"),
    );
    let swapped = swappable.join("app-flat").display().to_string();
    assert_reviewed(
        &home,
        &repository,
        &format!("{add} && cd {swapped} && git log -1"),
    );
    assert_reviewed(
        &home,
        &repository,
        "git worktree add -b flat ~/via/app-flat origin/main",
    );
}
