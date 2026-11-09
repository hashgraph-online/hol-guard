//! Listing a documentation pattern whose matches are named for credentials.
//!
//! A repository documents the credentials it rotates, so `docs` holds
//! `credential-rotation-runbook.md` next to the rest of the handbook. Listing
//! the directory prints that name, and so does a literal `ls` of the file, so
//! `ls docs/*.md` must print it too. A listing never opens what it names,
//! while a read of the same pattern still answers for the bytes behind it.
#![cfg(unix)]

use std::path::PathBuf;

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{assert_decision, repository};

struct World {
    _cleanup: fixture::FixtureCleanup,
    home: PathBuf,
    workspace: PathBuf,
}

fn world(tag: &str) -> World {
    let root = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-ls-documentation-{tag}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let home = root.join("home");
    let workspace = home.join("Code/app-portal");
    std::fs::create_dir_all(workspace.join("docs")).unwrap();
    for (name, body) in [
        ("architecture.md", "# Architecture\n"),
        ("credential-rotation-runbook.md", "# Rotating credentials\n"),
        ("secret-handling.md", "# Handling secrets\n"),
    ] {
        std::fs::write(workspace.join("docs").join(name), body).unwrap();
    }
    // The handbook is committed, the way a repository keeps its documentation.
    repository(&workspace);
    World {
        _cleanup: fixture::FixtureCleanup(root),
        home,
        workspace,
    }
}

/// `ls docs/*.md` prints the same names `ls docs` does, so a page named for
/// the credentials it describes cannot withdraw the listing's proof.
#[test]
fn a_documentation_pattern_lists_a_credential_named_page() {
    let world = world("allow");
    for command in [
        "ls docs/*.md",
        "ls -d docs/*.md",
        "ls docs/credential-rotation-runbook.md",
        "ls docs",
        "echo docs/*.md",
    ] {
        assert_decision(&world.workspace, &world.home, command, true);
    }
}

/// The same pattern handed to a reader opens every match, so it answers for
/// the bytes behind those names and keeps its review.
#[test]
fn a_read_of_the_same_pattern_still_asks() {
    let world = world("read");
    for command in ["cat docs/*.md", "head -5 docs/*.md"] {
        assert_decision(&world.workspace, &world.home, command, false);
    }
}

/// A match the sensitive families answer for is still a stored secret, and
/// naming it in a listing stays under review.
#[test]
fn a_listing_that_would_name_a_private_key_still_asks() {
    let world = world("sensitive");
    std::fs::write(world.workspace.join("docs/signing.key"), "fixture\n").unwrap();
    assert_decision(&world.workspace, &world.home, "ls docs/*", false);
}

/// A secret extension marks the match as a key container rather than as a
/// name that happens to read like one, so a listing that would print it keeps
/// its review as well.
#[test]
fn a_listing_that_would_name_a_key_container_still_asks() {
    let world = world("container");
    std::fs::write(world.workspace.join("docs/server.pem"), "fixture\n").unwrap();
    assert_decision(&world.workspace, &world.home, "ls docs/*", false);
}
