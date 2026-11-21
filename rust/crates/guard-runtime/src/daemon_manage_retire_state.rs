//! Journaling a retirement, and retiring the daemon one state record names.
//!
//! A retirement is journaled only once the process has passed the start
//! marker, owner and command checks, immediately before the first signal, so
//! a reused pid or a daemon that already died never gets a retirement it did
//! not have. A markerless state is never signalled and never journaled: its
//! daemon's end, if any, is left to the unclean-exit check.

use serde_json::{Map, Value};

use crate::daemon_edge::lifecycle;

use super::super::host::{self, Caller};
use super::super::records::{self, int, text};
use super::{retire_pid, Deadline, Expected};

/// Journals that `caller` is about to retire `pid`, and why, so the daemon's
/// end has a cause on record even though it cannot write one itself.
pub(in crate::daemon_manage) fn record_retirement(
    caller: &Caller,
    pid: i64,
    reason: Option<&str>,
    session_id: Option<&str>,
) {
    let (Some(reason), Ok(pid)) = (reason, u32::try_from(pid)) else {
        return;
    };
    let details = lifecycle::Details {
        reason: Some(reason),
        session_id,
        by_pid: u32::try_from(caller.own_pid).ok().filter(|pid| *pid > 0),
        by_parent_pid: u32::try_from(caller.parent_pid).ok().filter(|pid| *pid > 0),
        ..lifecycle::Details::default()
    };
    lifecycle::record_details(&caller.guard_home, pid, "retirement_requested", &details);
}

pub(super) fn retire_state_daemon(
    caller: &Caller,
    state: &Map<String, Value>,
    keep_port: Option<i64>,
    reason: &str,
    deadline: Deadline,
    handled: &mut Vec<i64>,
    retired: &mut Vec<i64>,
) {
    let home = caller.guard_home.as_path();
    let (Some(pid), Some(port)) = (int(state, "pid").filter(|pid| *pid > 0), int(state, "port"))
    else {
        return;
    };
    if keep_port == Some(port) {
        handled.push(pid);
        return;
    }
    if handled.contains(&pid) {
        if host::pid_is_proven_dead(pid) {
            records::clear_state_if_current(home, state);
        }
        return;
    }
    handled.push(pid);
    let succeeded = match text(state, "process_start_marker").filter(|m| !m.trim().is_empty()) {
        Some(marker) => {
            let expected = Expected {
                start_marker: Some(marker),
                owner_marker: text(state, "user").filter(|user| !user.is_empty()),
                reason: Some(reason),
                session_id: text(state, "state_id"),
                ..Expected::default()
            };
            retire_pid(caller, pid, &expected, deadline)
        }
        // A markerless state cannot name a pid generation: only a proven
        // exit counts, and nothing is signalled.
        None => host::pid_is_proven_dead(pid),
    };
    if !succeeded {
        return;
    }
    if host::pid_is_proven_dead(pid) {
        records::clear_state_if_current(home, state);
        if !retired.contains(&pid) {
            retired.push(pid);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::*;

    struct Running(Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn caller(home: &Path) -> Caller {
        Caller {
            guard_home: home.to_path_buf(),
            implicit_home: String::new(),
            own_pid: i64::from(std::process::id()),
            parent_pid: 0,
            frozen_runtime: false,
            frozen_parent_trusted: false,
            executable_name: None,
        }
    }

    fn retirements(home: &Path) -> usize {
        let Ok(entries) = std::fs::read_dir(home.join("daemon-lifecycle")) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|event| event["event"] == "retirement_requested")
            .count()
    }

    fn retire(home: &Path, state: &Value) {
        let state = state.as_object().unwrap();
        let deadline = Deadline(Some(Instant::now() + Duration::from_secs(2)));
        let (mut handled, mut retired) = (Vec::new(), Vec::new());
        retire_state_daemon(
            &caller(home),
            state,
            None,
            "unhealthy_published",
            deadline,
            &mut handled,
            &mut retired,
        );
        assert!(retired.is_empty());
    }

    #[test]
    fn a_state_naming_a_foreign_process_journals_no_retirement() {
        let home = tempfile::tempdir().unwrap();
        let mut foreign = Running(Command::new("sleep").arg("30").spawn().unwrap());
        let pid = foreign.0.id();
        // A reused pid: the state's start marker names another generation.
        retire(
            home.path(),
            &json!({
                "pid": pid,
                "port": 59733,
                "process_start_marker": "another-generation",
                "state_id": "state-1",
            }),
        );
        // A markerless state is never signalled, so it is never journaled.
        retire(
            home.path(),
            &json!({"pid": pid, "port": 59734, "state_id": "state-2"}),
        );
        assert_eq!(retirements(home.path()), 0);
        assert!(foreign.0.try_wait().unwrap().is_none());
    }
}
