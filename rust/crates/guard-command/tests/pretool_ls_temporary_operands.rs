//! Listings in the temporary area agents keep scratch work in.
//!
//! A name that is not there prints only an error, whatever it spells, and a
//! pattern below an owned temporary directory names its matches without
//! listing that directory itself. The home tree keeps its own answers: a
//! missing dot name there is still the secrets boundary, and a pattern never
//! reaches into a hidden directory or sits directly below the shared root.
//!
//! The fixture roots live below the shared temporary directory because that
//! is the root these screens are about; `CARGO_TARGET_TMPDIR` sits inside
//! this repository.
#![cfg(unix)]

use std::path::PathBuf;

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{assert_decision, repository};

struct World {
    _cleanup: fixture::FixtureCleanup,
    root: PathBuf,
    home: PathBuf,
    scratch: PathBuf,
    workspace: PathBuf,
}

fn world(tag: &str) -> World {
    let root = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-ls-temporary-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let home = root.join("home");
    let scratch = root.join("scratch");
    let workspace = home.join("Code/app-portal");
    for directory in [&workspace, &scratch.join("pg-run"), &home.join(".ssh")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    repository(&workspace);
    std::fs::write(scratch.join("notes.txt"), "first draft\n").unwrap();
    std::fs::write(scratch.join("pg-run/.s.PGSQL.5432.lock"), "4242\n").unwrap();
    std::fs::write(home.join(".ssh/config"), "Host fixture\n").unwrap();
    World {
        _cleanup: fixture::FixtureCleanup(root.clone()),
        root: fixture::canonical_spelling(root),
        home,
        scratch,
        workspace,
    }
}

/// A probe for a directory that is not there reads nothing, so the name it
/// spells cannot matter below a temporary directory only its owner writes.
/// Agents reach this shape constantly, checking a scratch checkout for an
/// optional `node_modules`, `.cache` or `.tmp`.
#[test]
fn a_missing_name_below_a_temporary_directory_prints_only_an_error() {
    let world = world("missing");
    let scratch = fixture::shell_word(&world.scratch);
    for command in [
        format!("ls {scratch}/.tmp"),
        format!("ls {scratch}/.cache/http"),
        format!("ls {scratch}/org/signup-funnel/.tmp"),
        format!("ls {scratch}/org/signup-funnel/node_modules"),
        format!("ls -la {scratch}/.tmp"),
    ] {
        assert_decision(&world.workspace, &world.home, &command, true);
    }
}

/// `ls /tmp/tmp.ab12/pg*` prints the matches, not the directory they sit in,
/// so below a temporary directory only its owner writes the pattern is
/// admitted by what it can name. Every match is screened on its own, exactly
/// as a pattern below any other listable directory is.
#[test]
fn a_pattern_below_an_owned_temporary_directory_names_its_matches() {
    let world = world("pattern");
    let scratch = fixture::shell_word(&world.scratch);
    for command in [format!("ls {scratch}/pg*"), format!("ls {scratch}/notes*")] {
        assert_decision(&world.workspace, &world.home, &command, true);
    }
}

/// Both shapes stop where the screens they lean on stop. The home tree keeps
/// its own answer although this fixture's home lives below the temporary
/// root: a missing dot name there is the secrets boundary, not an empty
/// probe. A pattern still never reaches into a hidden directory, never names
/// the directory it sits in, and never lists the temporary root whole. A
/// pattern directly below the shared root is reviewed too: the shell expands
/// it after the screen, and another user can plant a matching link there.
#[test]
fn the_home_tree_and_hidden_matches_keep_their_review() {
    let world = world("screens");
    let hidden = world.root.with_file_name(format!(
        ".{}",
        world.root.file_name().unwrap().to_string_lossy()
    ));
    std::fs::create_dir_all(hidden.join("inner")).unwrap();
    let _cleanup = fixture::FixtureCleanup(hidden.clone());
    let home = fixture::shell_word(&world.home);
    let root = fixture::shell_word(&world.root);
    for command in [
        format!("ls {root}*"),
        format!("ls -d {root}*"),
        format!("ls {}*", fixture::shell_word(&hidden)),
        format!("ls {home}/.secret-store/token"),
        format!("ls {home}/.ssh/missing-key"),
        format!("ls {home}/.*"),
        format!("ls {}/*", fixture::shell_word(world.root.parent().unwrap())),
    ] {
        assert_decision(&world.workspace, &world.home, &command, false);
    }
}
