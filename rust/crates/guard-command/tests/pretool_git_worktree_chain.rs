#![cfg(unix)]

use crate::worktree_chain_fixture::{assert_allowed, assert_reviewed, git, repository};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

/// The same reads when the add reports through a bounded pipe, when `;`
/// joins the `cd`, and when the reads name the index or count their own
/// output. The checkout proof read the destination and found nothing there,
/// so entering it succeeds only once the add has created it.
#[test]
fn inspecting_the_new_worktree_through_a_pipe_is_allowed() {
    let (_cleanup, home, repository) = repository("chain-pipe");
    for command in [
        "git worktree add ../app-flat -b flat origin/main 2>&1 | tail -3; cd ../app-flat && git rev-parse HEAD && git status --short | wc -l",
        "git worktree add -b flat ../app-flat origin/main 2>&1 | tail -3 && cd ../app-flat && git log -1 --oneline",
        "git worktree add -b flat ../app-flat origin/main; cd ../app-flat && git rev-parse --abbrev-ref HEAD",
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git ls-files | wc -l",
    ] {
        assert_allowed(&home, &repository, command);
    }
}

/// The relaxation rests on the `cd`: without one, a weaker separator proves
/// nothing about whether the add ran. The stages stay bounded, and the two
/// new reads keep the spellings that open a file the caller names or expand
/// a format under review.
#[test]
fn a_weaker_separator_without_the_cd_stays_reviewed() {
    let (_cleanup, home, repository) = repository("chain-pipe-reviewed");
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        "; git -C ../app-flat status",
        " 2>&1 | tail -3 && git -C ../app-flat status",
        " | cat && cd ../app-flat && git status",
        " && cd ../app-flat && git status --short | wc -l tracked.txt",
        " && cd ../app-flat && git ls-files --format=%(path)",
        " && cd ../app-flat && git ls-files -X ../exclude",
        " && cd ../app-flat && git rev-parse --sq-quote tracked.txt",
    ] {
        assert_reviewed(&home, &repository, &format!("{add}{tail}"));
    }
}

/// Agents end a worktree chain by saying what happened, and start one by
/// saying what they are about to do. `echo`, `pwd` and a bare listing write
/// no configuration the Git reads beside them could pick up, so they leave
/// the entered-checkout proof standing.
#[test]
fn read_only_steps_beside_the_reads_keep_the_checkout_proof() {
    let (_cleanup, home, repository) = repository("chain-inert");
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        " && cd ../app-flat && git status --short && echo CLEAN",
        " && cd ../app-flat && echo entering && git log -1 --oneline",
        " && cd ../app-flat && pwd && git status --short",
        " && cd ../app-flat && git status --short && ls",
        " && cd ../app-flat && git status --porcelain | head -3 && echo CLEAN",
        " && cd ../app-flat && true && git rev-parse --abbrev-ref HEAD",
    ] {
        assert_allowed(&home, &repository, &format!("{add}{tail}"));
    }
}

/// The step has to be read-only on the proof's own terms. A writer, a
/// redirect, a named environment value, a second `cd` and a program the new
/// checkout could supply each reach past what the destination proof answers
/// for, so the reads beside them stay reviewed.
#[test]
fn a_writing_step_beside_the_reads_still_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-inert-reviewed");
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        " && cd ../app-flat && touch marker && git status --short",
        " && cd ../app-flat && echo CLEAN > marker && git status --short",
        " && cd ../app-flat && GIT_CONFIG_GLOBAL=../other true && git status --short",
        " && cd ../app-flat && git status --short && cd .. && git status --short",
        " && cd ../app-flat && ./report.sh && git status --short",
        " && cd ../app-flat && rg --pre ./pre tracked && git status --short",
    ] {
        assert_reviewed(&home, &repository, &format!("{add}{tail}"));
    }
}

/// Agents name the branch they will work on right after making the checkout.
/// With no start point the branch begins at the commit the add already
/// proved, so the step changes no file and runs only the hooks that proof
/// covers.
#[test]
fn a_new_branch_in_the_entered_checkout_keeps_the_proof() {
    let (_cleanup, home, repository) = repository("chain-branch");
    let add = "git worktree add --detach ../app-flat origin/main";
    for tail in [
        " && cd ../app-flat && git checkout -b feat/landing && git rev-parse HEAD",
        " && cd ../app-flat && git switch -c feat/landing && git status --porcelain | head -3",
        " && cd ../app-flat && git checkout -b feat/landing && git status --porcelain | head -3 && echo READY",
    ] {
        assert_allowed(&home, &repository, &format!("{add}{tail}"));
    }
}

/// The step is proven only as a branch creation on the commit the add read.
/// A start point names another commit, a checkout of a path rewrites files
/// from the index, and a branch name spelled as an option or a parent step
/// is not a name the proof answers for.
#[test]
fn a_checkout_past_the_new_branch_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-branch-reviewed");
    let add = "git worktree add --detach ../app-flat origin/main";
    for tail in [
        " && cd ../app-flat && git checkout -b feat/landing origin/main~1 && git status --short",
        " && cd ../app-flat && git checkout -b feat/landing HEAD~1 && git status --short",
        " && cd ../app-flat && git checkout main && git status --short",
        " && cd ../app-flat && git checkout -- . && git status --short",
        " && cd ../app-flat && git checkout -b ../escape && git status --short",
        " && cd ../app-flat && git checkout -B feat/landing && git status --short",
        " && cd ../app-flat && git switch -c feat/landing origin/main && git status --short",
    ] {
        assert_reviewed(&home, &repository, &format!("{add}{tail}"));
    }
}

/// The same setup written with `-C` instead of a `cd`. An agent that already
/// routes the add into the repository routes the branch and the reads after
/// it the same way, and `-C` enters exactly the checkout the `cd` would.
#[test]
fn a_new_branch_routed_into_the_new_checkout_keeps_the_proof() {
    let (_cleanup, home, repository) = repository("chain-branch-routed");
    let repository_text = repository.display().to_string();
    for command in [
        "git worktree add --detach ../app-flat origin/main && git -C ../app-flat checkout -b feat/landing && git -C ../app-flat log --oneline -1".to_owned(),
        "git worktree add --detach ../app-flat origin/main && git -C ../app-flat switch -c feat/landing && git -C ../app-flat status --short".to_owned(),
        format!("git -C {repository_text} worktree add --detach ../app-flat origin/main && git -C ../app-flat checkout -b feat/landing && git -C ../app-flat rev-parse HEAD"),
    ] {
        assert_allowed(&home, &repository, &command);
    }
}

/// The routed step is proven as the same branch creation the `cd` spelling
/// proves, so a start point, a force-create and a `-C` that leaves the new
/// checkout all keep their review.
#[test]
fn a_routed_checkout_past_the_new_branch_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-branch-routed-reviewed");
    let add = "git worktree add --detach ../app-flat origin/main";
    for tail in [
        " && git -C ../app-flat checkout -b feat/landing origin/main~1 && git -C ../app-flat status --short",
        " && git -C ../app-flat checkout -B feat/landing && git -C ../app-flat status --short",
        " && git -C ../app-flat switch -c feat/landing origin/main && git -C ../app-flat status --short",
        " && git -C .. checkout -b feat/landing && git -C ../app-flat status --short",
    ] {
        assert_reviewed(&home, &repository, &format!("{add}{tail}"));
    }
}
