#![forbid(unsafe_code)]

use crate::resident_state::{discover_states, ResidentState};
use std::path::Path;
use std::time::Instant;

fn includes(stopped: &[ResidentState], state: &ResidentState) -> bool {
    stopped.iter().any(|captured| {
        captured.generation == state.generation
            && captured.process_id == state.process_id
            && captured.process_start_marker == state.process_start_marker
    })
}

pub(super) fn capture(
    scope: &Path,
    digest: &str,
    selected: &ResidentState,
) -> Result<Vec<ResidentState>, String> {
    let mut stopped = discover_states(scope, digest)?;
    if !includes(&stopped, selected) {
        stopped.push(selected.clone());
    }
    Ok(stopped)
}

pub(super) fn capture_for_stop(
    scope: &Path,
    digest: &str,
    selected: &ResidentState,
    retire_clients: bool,
) -> Result<Vec<ResidentState>, String> {
    if cfg!(unix) && !retire_clients {
        capture(scope, digest, selected)
    } else {
        Ok(Vec::new())
    }
}

pub(super) fn wait(
    scope: &Path,
    digest: &str,
    deadline: Instant,
    stopped: &[ResidentState],
) -> Result<(), String> {
    let known = super::containment::state_process_identities(stopped);
    // A live caller can start a fresh generation after the acknowledged one
    // releases its owner lock. Neither wait for nor terminate that new owner.
    super::containment::wait_for_matching_stop_containment(
        scope,
        digest,
        deadline,
        &known,
        |state| includes(stopped, state),
    )
}

pub(super) fn wait_for_stop(
    scope: &Path,
    digest: &str,
    deadline: Instant,
    stopped: &[ResidentState],
    selected: &ResidentState,
    retire_clients: bool,
) -> Result<(), String> {
    if cfg!(unix) && !retire_clients {
        wait(scope, digest, deadline, stopped)
    } else {
        let known = super::containment::state_process_identities(std::slice::from_ref(selected));
        super::containment::wait_for_stop_containment(scope, digest, deadline, &known)
    }
}

#[cfg(all(test, unix))]
#[path = "managed_resident_stop_snapshot_tests.rs"]
mod tests;
