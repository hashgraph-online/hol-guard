//! Retiring the daemons of one Guard home (`_retire_guard_daemons_for_home`,
//! `_retire_guard_daemon_pid` and `guard_daemon_retirement_is_complete`).
//!
//! A process is signalled only after its exact generation is admitted: its
//! start marker, its owner and its command line must name this home's
//! daemon, and each is checked again immediately before each signal.

use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::daemon_edge::lifecycle;
use crate::daemon_policy_authority::{
    load_authenticated_daemon_identity, load_authenticated_daemon_state,
};

use super::host::{self, Caller};
use super::records::{self, int, owner, text};

const DEFAULT_WAIT: Duration = Duration::from_secs(1);
const ORPHAN_REAP_TIMEOUT: Duration = Duration::from_secs(15);
const ORPHAN_REAP_LAUNCH_RESERVE: Duration = Duration::from_millis(250);
const ORPHAN_REAP_MAX_BUDGET_MS: u128 = 60_000;

/// What one retirement attempt may expect of the process it signals.
#[derive(Default)]
pub(super) struct Expected<'a> {
    pub(super) creation_time: Option<i64>,
    pub(super) start_marker: Option<&'a str>,
    pub(super) owner_marker: Option<&'a str>,
}

/// The shared deadline of one management request.
#[derive(Clone, Copy)]
pub(super) struct Deadline(pub(super) Option<Instant>);

impl Deadline {
    pub(super) fn passed(self) -> bool {
        self.0.is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub(super) fn remaining(self) -> Option<Duration> {
        self.0
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
}

fn start_marker_matches(pid: i64, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    host::start_marker(pid).is_some_and(|actual| host::same_text(&actual, expected))
}

fn owner_marker_matches(pid: i64, expected: Option<&str>) -> bool {
    let wanted = match expected.filter(|owner| !owner.is_empty()) {
        Some(owner) => Some(owner.to_owned()),
        None => host::own_owner_marker(),
    };
    match (wanted, host::owner_marker(pid)) {
        (Some(wanted), Some(actual)) => host::same_text(&actual, &wanted),
        _ => false,
    }
}

/// `_retire_guard_daemon_process`: one recorded generation, by its start
/// marker and owner.
pub(super) fn retire_generation(
    caller: &Caller,
    pid: i64,
    start_marker: &str,
    owner_marker: Option<&str>,
    deadline: Deadline,
) -> bool {
    let expected = Expected {
        creation_time: None,
        start_marker: Some(start_marker),
        owner_marker,
    };
    retire_pid(caller, pid, &expected, deadline)
}

/// `_retire_guard_daemon_pid`.
pub(super) fn retire_pid(
    caller: &Caller,
    pid: i64,
    expected: &Expected<'_>,
    deadline: Deadline,
) -> bool {
    let marker = expected.start_marker;
    let wait = || match deadline.remaining() {
        None => host::wait_for_death(pid, DEFAULT_WAIT),
        Some(remaining) => host::wait_for_death(pid, remaining.min(DEFAULT_WAIT)),
    };
    let terminate_exact = |creation_time: i64| {
        start_marker_matches(pid, marker)
            && owner_marker_matches(pid, expected.owner_marker)
            && host::windows_terminate_if_creation_time(pid, creation_time, deadline.remaining())
    };
    if host::pid_is_proven_dead(pid) {
        return true;
    }
    if deadline.passed() {
        return false;
    }
    if !host::nt() && marker.is_none_or(str::is_empty) {
        return false;
    }
    if !start_marker_matches(pid, marker) {
        return false;
    }
    if host::nt() {
        if let Some(creation_time) = expected.creation_time {
            return terminate_exact(creation_time);
        }
    }
    let observed_creation_time = if host::nt() {
        match host::windows_creation_time(pid) {
            Some(time) => Some(time),
            None => return false,
        }
    } else {
        None
    };
    let identity = host::command_identity(caller, pid, Some(&caller.guard_home));
    if identity != Some(true) {
        // Another command now owns the pid: nothing of ours to stop, so the
        // caller may clear the stale state. An unreadable command fails closed.
        return identity == Some(false);
    }
    if let Some(creation_time) = observed_creation_time {
        return terminate_exact(creation_time);
    }
    for kill_now in [false, true] {
        if deadline.passed() {
            return host::pid_is_proven_dead(pid);
        }
        if !start_marker_matches(pid, marker) || !owner_marker_matches(pid, expected.owner_marker) {
            return false;
        }
        match host::signal(pid, kill_now) {
            Ok(false) => return true,
            Err(()) => return host::pid_is_proven_dead(pid),
            Ok(true) => {}
        }
        if wait() {
            return true;
        }
    }
    false
}

/// `_guard_daemon_pid_identity_for_retirement`: the generation and owner an
/// inventoried process must keep, when it runs as this user.
pub(super) fn identity_for_retirement(pid: i64) -> Option<(String, String)> {
    let marker = host::start_marker(pid)?;
    let owner = host::owner_marker(pid)?;
    let own = host::own_owner_marker()?;
    host::same_text(&owner, &own).then_some((marker, owner))
}

/// `_guard_daemon_pending_launch_is_abandoned`.
fn pending_is_abandoned(pending: Option<&Map<String, Value>>) -> bool {
    let Some(pending) = pending.filter(|p| records::is_generation_bound(Some(p))) else {
        return false;
    };
    let (Some(pid), Some(marker)) = (
        int(pending, "pid").filter(|pid| *pid > 0),
        text(pending, "process_start_marker").filter(|m| !m.is_empty()),
    ) else {
        return false;
    };
    if host::pid_is_proven_dead(pid) {
        return true;
    }
    // A live pid that started at another moment is a reused pid.
    if host::nt() {
        let expected = int(pending, "process_creation_time");
        return matches!((expected, host::windows_creation_time(pid)), (Some(e), Some(a)) if a != e);
    }
    host::start_marker(pid).is_some_and(|actual| actual != marker)
}

/// `_guard_daemon_pid_is_spawned_launch`.
pub(super) fn is_spawned_launch(caller: &Caller, pid: i64, root: i64) -> bool {
    if root <= 0 {
        return false;
    }
    if pid == root {
        return true;
    }
    if !host::pid_is_running(root) {
        return false;
    }
    if host::nt() {
        if let (Some(root_created), Some(created)) = (
            host::windows_creation_time(root),
            host::windows_creation_time(pid),
        ) {
            if created < root_created {
                return false;
            }
        }
        let (Some(left), Some(right)) = (host::command_for_pid(root), host::command_for_pid(pid))
        else {
            return false;
        };
        let query = json!({"check": "same_invocation", "left": left, "right": right});
        return host::lifecycle(caller, query)
            .and_then(|verdict| verdict.get("same").and_then(Value::as_bool))
            .unwrap_or(false);
    }
    host::parent_pid(pid) == Some(root)
}

/// `_guard_daemon_handoff_matches_launch` with `require_same_runtime=False`.
pub(super) fn handoff_matches_launch(caller: &Caller, nonce: &str, expected_pid: i64) -> bool {
    let home = &caller.guard_home;
    if !records::nonce_is_valid(Some(&Value::from(nonce))) || expected_pid <= 0 {
        return false;
    }
    let (Some(pending), Some((state, _))) = (
        records::load_pending(home),
        load_authenticated_daemon_identity(home),
    ) else {
        return false;
    };
    let expected_home = Value::from(host::resolve_lenient(home).to_string_lossy().into_owned());
    let nonce_value = Value::from(nonce);
    let binds = |map: &Map<String, Value>| {
        map.get("guard_home") == Some(&expected_home)
            && ["launch_nonce", "launch_generation", "generation"]
                .iter()
                .all(|key| map.get(*key) == Some(&nonce_value))
    };
    if !binds(&pending)
        || !binds(&state)
        || int(&pending, "pid") != Some(expected_pid)
        || pending.get("port") != state.get("port")
        || owner(&pending) != owner(&state)
    {
        return false;
    }
    if host::nt() && pending.get("process_creation_time") != state.get("process_creation_time") {
        return false;
    }
    let filled = |map: &Map<String, Value>, key: &str| {
        text(map, key)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let pending_owner = owner(&pending)
        .and_then(Value::as_str)
        .filter(|o| !o.is_empty());
    let state_owner = owner(&state).and_then(Value::as_str);
    let (
        Some(pending_marker),
        Some(pending_owner),
        Some(state_pid),
        Some(state_marker),
        Some(state_owner),
    ) = (
        filled(&pending, "process_start_marker"),
        pending_owner,
        int(&state, "pid").filter(|pid| *pid > 0),
        filled(&state, "process_start_marker"),
        state_owner,
    )
    else {
        return false;
    };
    if state_owner != pending_owner {
        return false;
    }
    let generation_is = |pid: i64, marker: &str, owner: &str| {
        host::start_marker(pid).as_deref() == Some(marker)
            && host::owner_marker(pid).as_deref() == Some(owner)
    };
    if !generation_is(expected_pid, &pending_marker, pending_owner)
        || !generation_is(state_pid, &state_marker, state_owner)
    {
        return false;
    }
    state_pid == expected_pid || is_spawned_launch(caller, state_pid, expected_pid)
}

/// `resolve_handed_off_guard_daemon_pending_launch`.
fn resolve_handed_off(caller: &Caller, pending: Option<&Map<String, Value>>) -> bool {
    let Some(pending) = pending.filter(|p| records::is_generation_bound(Some(p))) else {
        return false;
    };
    let (Some(pid), Some(nonce), Some(marker)) = (
        int(pending, "pid"),
        text(pending, "launch_nonce"),
        text(pending, "process_start_marker"),
    ) else {
        return false;
    };
    handoff_matches_launch(caller, nonce, pid)
        && records::clear_pending_if_current(
            &caller.guard_home,
            pid,
            int(pending, "process_creation_time"),
            Some(nonce),
            Some(marker),
        )
}

/// `_resolve_abandoned_guard_daemon_pending_launch`.
pub(super) fn resolve_abandoned(caller: &Caller, pending: Option<&Map<String, Value>>) -> bool {
    if resolve_handed_off(caller, pending) {
        return true;
    }
    let Some(pending) = pending.filter(|p| pending_is_abandoned(Some(p))) else {
        return false;
    };
    if host::daemon_inventory(caller).as_deref() != Some(&[]) {
        return false;
    }
    let Some(pid) = int(pending, "pid") else {
        return false;
    };
    records::clear_pending_if_current(
        &caller.guard_home,
        pid,
        int(pending, "process_creation_time"),
        Some(text(pending, "launch_nonce").unwrap_or_default()),
        Some(text(pending, "process_start_marker").unwrap_or_default()),
    )
}

/// `_retire_guard_daemons_for_home`: the pids it proved stopped.
pub(super) fn retire_all(caller: &Caller, keep_port: Option<i64>, deadline: Deadline) -> Vec<i64> {
    let home = caller.guard_home.as_path();
    let mut retired: Vec<i64> = Vec::new();
    let mut handled: Vec<i64> = Vec::new();
    let pending = records::load_pending(home);
    let mut handed_off_nonce: Option<Value> = None;
    if records::is_generation_bound(pending.as_ref())
        && !records::pending_is_resolved(home)
        && !pending_is_abandoned(pending.as_ref())
    {
        // A live launch stays unresolved until it publishes its handoff:
        // inventory cannot prove a process is not one of its descendants.
        if !resolve_handed_off(caller, pending.as_ref()) {
            return retired;
        }
        handed_off_nonce = pending
            .as_ref()
            .and_then(|p| p.get("launch_nonce").cloned());
    }
    if let Some(pending) = &pending {
        if let (Some(pid), Some(creation_time)) =
            (int(pending, "pid"), int(pending, "process_creation_time"))
        {
            if keep_port.is_some() && int(pending, "port") == keep_port {
                handled.push(pid);
            } else {
                let actual = host::windows_creation_time(pid);
                if actual == Some(creation_time) {
                    handled.push(pid);
                    let expected = Expected {
                        creation_time: Some(creation_time),
                        ..Expected::default()
                    };
                    if retire_pid(caller, pid, &expected, deadline) && host::pid_is_proven_dead(pid)
                    {
                        retired.push(pid);
                        records::clear_pending_if_current(
                            home,
                            pid,
                            Some(creation_time),
                            None,
                            None,
                        );
                    }
                } else if actual.is_some() || host::pid_is_proven_dead(pid) {
                    records::clear_pending_if_current(home, pid, Some(creation_time), None, None);
                } else {
                    handled.push(pid);
                }
            }
        }
    }

    let state = load_authenticated_daemon_state(home);
    if let Some(nonce) = &handed_off_nonce {
        // A start replaced the handed-off daemon after its receipt cleared;
        // that launch owns the home now.
        if !records::pending_is_resolved(home)
            || state
                .as_ref()
                .is_some_and(|state| state.get("launch_nonce") != Some(nonce))
        {
            return retired;
        }
    }
    if let Some(state) = &state {
        retire_state_daemon(
            caller,
            state,
            keep_port,
            deadline,
            &mut handled,
            &mut retired,
        );
    }

    if let Some(inventory) = host::daemon_inventory(caller) {
        for &(pid, port) in &inventory {
            if handled.contains(&pid) || keep_port == Some(port) {
                continue;
            }
            let Some((marker, owner)) = identity_for_retirement(pid) else {
                continue;
            };
            let expected = Expected {
                start_marker: Some(&marker),
                owner_marker: Some(&owner),
                ..Expected::default()
            };
            if retire_pid(caller, pid, &expected, deadline) && host::pid_is_proven_dead(pid) {
                handled.push(pid);
                if !retired.contains(&pid) {
                    retired.push(pid);
                }
            }
        }
        let remaining = host::daemon_inventory(caller);
        let empty = Some(Vec::new());
        let confirmed = if inventory.is_empty() {
            remaining == empty
        } else {
            remaining == empty && host::daemon_inventory(caller) == empty
        };
        if confirmed && keep_port.is_none() {
            records::reconcile_invalid(home);
            resolve_abandoned(caller, pending.as_ref());
        }
    }
    reap_orphaned_workers(caller, deadline);
    retired
}

fn retire_state_daemon(
    caller: &Caller,
    state: &Map<String, Value>,
    keep_port: Option<i64>,
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
    if let Ok(raw_pid) = u32::try_from(pid) {
        lifecycle::record_for_pid(
            home,
            raw_pid,
            "retirement_requested",
            Some("managed_retirement"),
            text(state, "state_id"),
        );
    }
    let succeeded = match text(state, "process_start_marker").filter(|m| !m.trim().is_empty()) {
        Some(marker) => {
            let expected = Expected {
                start_marker: Some(marker),
                owner_marker: text(state, "user").filter(|user| !user.is_empty()),
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
    } else if host::command_identity(caller, pid, Some(home)) == Some(false) {
        records::clear_state_if_current(home, state);
    }
}

/// `reap_orphaned_daemon_workers`.
pub(super) fn reap_orphaned_workers(caller: &Caller, deadline: Deadline) {
    if host::nt() {
        return;
    }
    let deadline = deadline
        .0
        .unwrap_or_else(|| Instant::now() + ORPHAN_REAP_TIMEOUT);
    let budget = deadline
        .saturating_duration_since(Instant::now())
        .saturating_sub(ORPHAN_REAP_LAUNCH_RESERVE);
    if budget.is_zero() {
        return;
    }
    let request = json!({
        "schema": "orphaned-worker-reap.v1",
        "self_pid": caller.own_pid,
        "budget_ms": budget.as_millis().min(ORPHAN_REAP_MAX_BUDGET_MS),
    });
    let text = request.to_string();
    let _ = crate::orphaned_worker_reap::run_command(text.as_bytes());
}

/// `guard_daemon_retirement_is_complete`.
pub(super) fn retirement_is_complete(caller: &Caller) -> bool {
    let home = caller.guard_home.as_path();
    if let Some(state) = load_authenticated_daemon_state(home) {
        let Some(pid) = int(&state, "pid").filter(|pid| *pid > 0) else {
            return false;
        };
        if !host::pid_is_proven_dead(pid) {
            return false;
        }
    } else {
        let path = records::state_path(home);
        if path.is_file() && !records::is_exact_tombstone(&path) {
            return false;
        }
    }
    if !records::pending_is_resolved(home)
        && !resolve_abandoned(caller, records::load_pending(home).as_ref())
    {
        return false;
    }
    host::daemon_inventory(caller).as_deref() == Some(&[])
}

/// `_guard_daemon_pid_command_identity` for a state pid that is running.
pub(super) fn live_identity(caller: &Caller, pid: i64) -> Option<bool> {
    host::command_identity(caller, pid, Some(&caller.guard_home))
}
