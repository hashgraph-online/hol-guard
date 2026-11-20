//! Bring this Guard home's resident up when the daemon starts.
//!
//! A Claude Code session already prewarms the resident from its SessionStart
//! hook. Codex and Cursor have no such hook, so their first tool call paid for
//! the whole resident start. The daemon is started for every harness, after
//! install and on the first hook, so it starts the same detached
//! `resident-prewarm` the SessionStart lane does: the resident's own `health`
//! operation, held for a bounded window and then released. It decides
//! nothing, produces no verdict, receipt or approval, and a prewarm that fails
//! leaves the first hook exactly where it was. `managed_resident_prewarm.rs`
//! has the whole contract.
//!
//! Only a daemon running its background jobs prewarms, which is every daemon
//! the Guard launcher starts. A test Guard home (a `pytest-` directory) is
//! skipped, so a suite that starts hundreds of daemons does not also start
//! hundreds of residents.

use std::path::Path;
use std::process::{Command, Stdio};

const PREWARM_MODE: &str = "resident-prewarm";
const RESIDENT_STATE_DIRECTORY: &str = "native-runtime";

/// Start the detached prewarm for `home`, and reap it on a thread of its own
/// so a long-lived daemon does not keep a finished child as a zombie.
pub(super) fn prewarm_resident(home: &Path) {
    if ephemeral_home(home) {
        return;
    }
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Ok(mut child) = prewarm_command(&executable, home).spawn() else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("resident-prewarm-reaper".to_owned())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn prewarm_command(executable: &Path, home: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .arg(PREWARM_MODE)
        .arg("--state-dir")
        .arg(home.join(RESIDENT_STATE_DIRECTORY))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The hold outlives nothing of the daemon's, but a signal sent to the
    // daemon's group on shutdown must not cut a prewarm short mid-start.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
}

/// The same rule the daemon lifecycle applies to a Guard home under a pytest
/// temporary directory.
pub(super) fn ephemeral_home(home: &Path) -> bool {
    home.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        part.starts_with("pytest-") || part.contains("pytest-of-")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prewarm_is_the_session_start_lane_for_this_home() {
        let home = Path::new("/home/user/.hol-guard");
        let command = prewarm_command(Path::new("/opt/hol-guard-runtime"), home);

        assert_eq!(command.get_program(), "/opt/hol-guard-runtime");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], PREWARM_MODE);
        assert_eq!(args[1], "--state-dir");
        assert_eq!(Path::new(args[2]), home.join("native-runtime"));
    }

    #[test]
    fn only_a_pytest_home_is_ephemeral() {
        assert!(ephemeral_home(Path::new(
            "/private/var/folders/x/T/pytest-of-user/pytest-7/test_a0/guard"
        )));
        assert!(ephemeral_home(Path::new("/tmp/pytest-12/guard")));
        assert!(!ephemeral_home(Path::new("/home/user/.hol-guard")));
        assert!(!ephemeral_home(Path::new("/home/user/pytest/.hol-guard")));
    }
}
