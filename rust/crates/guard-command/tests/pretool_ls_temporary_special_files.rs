//! `ls` of a server socket, a named pipe or a missing lock name in the shared
//! temporary root.
//!
//! Agents check whether a local database is up with
//! `ls /tmp/.s.PGSQL.5432`. A listing stats the socket and never opens it,
//! and a name that is not there prints only an error. The home tree's own
//! answers and the credential store screens are unchanged.
#![cfg(unix)]

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{assert_decision, decide_with_shell_home, repository};

/// Removes plain entries placed directly in the shared temporary root.
struct EntryCleanup(Vec<PathBuf>);

impl Drop for EntryCleanup {
    fn drop(&mut self) {
        for entry in &self.0 {
            let _ = std::fs::remove_file(entry);
        }
    }
}

struct World {
    _cleanup: fixture::FixtureCleanup,
    _entries: EntryCleanup,
    _listeners: Vec<UnixListener>,
    home: PathBuf,
    scratch: PathBuf,
    workspace: PathBuf,
    tag: String,
}

fn shared_root() -> PathBuf {
    std::fs::canonicalize("/tmp").unwrap()
}

fn fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo {}", path.display());
}

fn world(tag: &str) -> World {
    let tag = format!(
        "{tag}{}x{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos() % 1_000_000
    );
    let root = shared_root().join(format!("guard-ls-special-{tag}"));
    let home = root.join("home");
    let scratch = root.join("scratch");
    let workspace = home.join("Code/app-portal");
    for directory in [&workspace, &scratch, &home.join(".ssh")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    repository(&workspace);
    std::fs::write(scratch.join(".s.PGSQL.5432.lock"), "4242\n").unwrap();
    let shared = shared_root();
    let socket = shared.join(format!(".s.GUARD.{tag}"));
    let pipe = shared.join(format!(".guard-pipe-{tag}"));
    let link = shared.join(format!(".guard-link-{tag}"));
    let entries = EntryCleanup(vec![socket.clone(), pipe.clone(), link.clone()]);
    let listeners = vec![
        UnixListener::bind(&socket).unwrap(),
        UnixListener::bind(scratch.join(".s.PGSQL.5432")).unwrap(),
        UnixListener::bind(home.join(".ssh/agent.sock")).unwrap(),
        UnixListener::bind(workspace.join(".s.APP")).unwrap(),
    ];
    fifo(&pipe);
    std::os::unix::fs::symlink(&socket, &link).unwrap();
    World {
        _cleanup: fixture::FixtureCleanup(root),
        _entries: entries,
        _listeners: listeners,
        home,
        scratch,
        workspace,
        tag,
    }
}

/// A socket or a pipe holds no bytes a listing could print, and a missing
/// lock name below the shared root prints `No such file or directory`.
#[test]
fn a_server_socket_or_missing_lock_name_in_the_temporary_root_is_listed() {
    let world = world("allow");
    let shared = fixture::shell_word(&shared_root());
    let scratch = fixture::shell_word(&world.scratch);
    let tag = &world.tag;
    for command in [
        format!("ls {shared}/.s.GUARD.{tag}"),
        format!("ls -la {shared}/.s.GUARD.{tag}"),
        format!("ls -l {shared}/.guard-pipe-{tag}"),
        format!("ls -la {scratch}/.s.PGSQL.5432"),
        format!("ls {scratch}/.s.PGSQL* 2>&1 | head -4"),
        format!("ls {shared}/.s.GUARD.{tag}-missing 2>/dev/null"),
        format!("ls -la {shared}/.guard-lock-{tag} 2>/dev/null"),
        format!("ls /tmp/.s.GUARD.{tag}"),
        format!("ls /tmp/.s.GUARD.{tag}-missing 2>/dev/null"),
    ] {
        assert_decision(&world.workspace, &world.home, &command, true);
    }
}

/// A link to a socket, a socket inside a credential store, a missing
/// credential store or secret file name, and a missing name two levels down
/// keep their review.
#[test]
fn links_stores_and_deeper_missing_names_keep_their_review() {
    let world = world("review");
    let shared = fixture::shell_word(&shared_root());
    let home = fixture::shell_word(&world.home);
    let tag = &world.tag;
    let mut commands = vec![
        format!("ls -la {shared}/.guard-link-{tag}"),
        format!("ls -la {home}/.ssh/agent.sock"),
        format!("ls {shared}/.guard-missing-{tag}/.inner"),
    ];
    for name in [".aws", ".ssh", ".netrc", ".env", ".env.local", ".npmrc"] {
        if std::fs::symlink_metadata(shared_root().join(name)).is_err() {
            commands.push(format!("ls -la {shared}/{name}"));
        }
    }
    for command in commands {
        assert_decision(&world.workspace, &world.home, &command, false);
    }
}

/// The shell expands `~` from its own HOME. When that is not the declared
/// home, `~/…` names some other file than the one the screens resolved, so a
/// socket named through `~` keeps its review.
#[test]
fn a_home_spelled_socket_needs_the_shell_to_share_the_home() {
    let world = world("home");
    let command = "ls -la ~/Code/app-portal/.s.APP";
    let shared = decide_with_shell_home(&world.workspace, &world.home, command, true);
    assert_eq!(
        (shared.decision.as_str(), shared.reason_code.as_str()),
        ("allow", "native_exact_safe_command"),
        "{command}"
    );
    let other = decide_with_shell_home(&world.workspace, &world.home, command, false);
    assert_ne!(other.decision, "allow", "{command}: {}", other.reason_code);
}
