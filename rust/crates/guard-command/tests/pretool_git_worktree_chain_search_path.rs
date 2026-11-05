//! The search path the `git worktree add` chain proof runs against. After the
//! `cd` the shell looks its programs up again, so an entry the new checkout
//! supplies decides what `git`, `gh` and every printing step beside them run.
#![cfg(unix)]

use crate::worktree_chain_fixture::{
    assert_allowed_on_search_path, assert_reviewed_on_search_path, repository,
};

/// `git worktree add` refuses a destination that already exists, so nothing
/// but the checked-out ref can fill a search path entry inside it. The chain
/// would otherwise answer for Git reads whose `git` came from the tree it
/// just checked out, and for printing steps beside them.
#[test]
fn a_search_path_entry_inside_the_new_checkout_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-inside");
    let checkout = repository.parent().unwrap().join("app-flat");
    let add = "git worktree add -b flat ../app-flat origin/main";
    for entry in [checkout.join("bin"), checkout.clone()] {
        for tail in [
            " && cd ../app-flat && git status --short",
            " && cd ../app-flat && git status --short && echo CLEAN",
            " && cd ../app-flat && git status --porcelain | head -3",
        ] {
            assert_reviewed_on_search_path(&home, &repository, &entry, &format!("{add}{tail}"));
        }
    }
}

/// A symbolic link that leads into the checkout says the same thing one step
/// removed. It dangles until the add runs, so resolving it on disk first
/// would find nothing to screen.
#[test]
fn a_search_path_link_into_the_new_checkout_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-link");
    let checkout = repository.parent().unwrap().join("app-flat");
    let shim = repository.parent().unwrap().join("shim");
    std::os::unix::fs::symlink(checkout.join("bin"), &shim).unwrap();
    assert_reviewed_on_search_path(
        &home,
        &repository,
        &shim,
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git status --short",
    );
}

/// The screen compares whole path components. A directory whose name merely
/// begins with the checkout's is outside it, and a chain beside one keeps the
/// proof it had.
#[test]
fn a_search_path_entry_beside_the_new_checkout_keeps_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-beside");
    let beside = repository.parent().unwrap().join("app-flat-tools");
    std::fs::create_dir_all(&beside).unwrap();
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        " && cd ../app-flat && git status --short",
        " && cd ../app-flat && git status --short && echo CLEAN",
    ] {
        assert_allowed_on_search_path(&home, &repository, &beside, &format!("{add}{tail}"));
    }
}
