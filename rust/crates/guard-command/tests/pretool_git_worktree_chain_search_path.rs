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

/// A search path entry can name the checkout without sharing a component
/// with it. `<repository>/../app-flat/bin` steps back out of the repository
/// and into the destination, so the entry has to be resolved the way the
/// kernel resolves it before it is compared.
#[test]
fn a_parent_step_into_the_new_checkout_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-parent-step");
    let entry = repository.join("..").join("app-flat").join("bin");
    assert_reviewed_on_search_path(
        &home,
        &repository,
        &entry,
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git status --short",
    );
}

/// A symbolic link above the entry leads into the checkout just as one at
/// the entry does. Nothing exists at the entry itself until the add runs, so
/// the link has to be followed through the deepest ancestor that does exist.
#[test]
fn a_linked_ancestor_of_the_new_checkout_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-linked-parent");
    let parent = repository.parent().unwrap().to_path_buf();
    let link = parent.join("org-link");
    std::os::unix::fs::symlink(&parent, &link).unwrap();
    let entry = link.join("app-flat").join("bin");
    assert_reviewed_on_search_path(
        &home,
        &repository,
        &entry,
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git status --short",
    );
}

/// A link whose target cannot be resolved says nothing about where the shell
/// will land once the add has filled the destination. Both of these lead
/// into the checkout -- `../app-flat/bin` read from `tools/`, and a second
/// link pointing at the first -- and neither resolves while the destination
/// is still missing, so the chain keeps no proof over them.
#[test]
fn a_search_path_link_that_resolves_nowhere_revokes_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-link-chain");
    let parent = repository.parent().unwrap().to_path_buf();
    let tools = parent.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let inner = tools.join("inner-shim");
    std::os::unix::fs::symlink("../app-flat/bin", &inner).unwrap();
    let outer = parent.join("outer-shim");
    std::os::unix::fs::symlink(&inner, &outer).unwrap();
    let add = "git worktree add -b flat ../app-flat origin/main";
    for entry in [inner, outer] {
        assert_reviewed_on_search_path(
            &home,
            &repository,
            &entry,
            &format!("{add} && cd ../app-flat && git status --short"),
        );
    }
}

/// Resolving the entry must not turn an ordinary spelling into a block. A
/// parent step that lands beside the checkout, and a link chain that ends
/// outside it, both name a folder the checkout never fills.
#[test]
fn a_resolved_entry_outside_the_new_checkout_keeps_the_proof() {
    let (_cleanup, home, repository) = repository("chain-path-resolved-beside");
    let parent = repository.parent().unwrap().to_path_buf();
    let beside = parent.join("app-flat-tools");
    std::fs::create_dir_all(&beside).unwrap();
    let inner = parent.join("tools-shim");
    std::os::unix::fs::symlink(&beside, &inner).unwrap();
    let outer = parent.join("outer-tools-shim");
    std::os::unix::fs::symlink(&inner, &outer).unwrap();
    let add = "git worktree add -b flat ../app-flat origin/main";
    for entry in [repository.join("..").join("app-flat-tools"), inner, outer] {
        assert_allowed_on_search_path(
            &home,
            &repository,
            &entry,
            &format!("{add} && cd ../app-flat && git status --short"),
        );
    }
}
