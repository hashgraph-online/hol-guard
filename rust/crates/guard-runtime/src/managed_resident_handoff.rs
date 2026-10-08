#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Instant;

use super::{containment, lease, MANAGED_STOP_TIMEOUT};
use crate::resident_state::{
    process_parent_id, process_start_marker, token_from_state, ResidentState,
};

/// A side-by-side update leaves the previous runtime's resident running after
/// its owner exits. Older runtimes count every client lease in the home, so
/// newer clients keep that resident alive while it holds the home-wide owner
/// lock and can never acknowledge their policy. Such a resident serves no
/// client of its own runtime.
pub(super) fn is_orphaned_foreign_resident(
    state_base: &Path,
    state: &ResidentState,
    runtime_digest: &str,
) -> bool {
    state.runtime_sha256 != runtime_digest
        && !owner_is_live(state)
        && !lease::any_live(state_base, &state.runtime_sha256)
}

/// The recorded owner of a supervised resident is its own supervisor, which
/// outlives the client that launched it. That client is gone once the
/// supervisor has been reparented to init or its parent has exited. Any other
/// parent, such as a subreaper, counts as a live owner.
fn owner_is_live(state: &ResidentState) -> bool {
    if !containment::state_owner_is_live(state) {
        return false;
    }
    if process_parent_id(state.process_id) != Some(state.owner_process_id) {
        return true;
    }
    process_parent_id(state.owner_process_id)
        .is_some_and(|launcher| launcher != 1 && process_start_marker(launcher).is_ok())
}

/// Stop an orphaned foreign resident through its authenticated shutdown and
/// wait for its processes to exit. Returns false when the shutdown was not
/// delivered, in which case the caller keeps using the resident as before.
pub(super) fn retire_orphaned_foreign_resident(
    scope: &Path,
    state: &ResidentState,
    deadline: Instant,
) -> bool {
    let deadline = deadline.min(Instant::now() + MANAGED_STOP_TIMEOUT);
    let Ok(token) = token_from_state(state) else {
        return false;
    };
    let process_ids = containment::state_process_identities(std::slice::from_ref(state));
    let identity = crate::resident_client::ExpectedProcessIdentity {
        process_id: state.process_id,
        start_marker: &state.process_start_marker,
        digest: Some(&state.runtime_sha256),
    };
    if crate::resident_client::send_request_for_digest(
        &state.transport,
        &state.endpoint,
        &token,
        br#"{"operation":"shutdown","request":{}}"#,
        deadline.saturating_duration_since(Instant::now()),
        &identity,
    )
    .is_err()
    {
        return false;
    }
    // The caller's startup path reports an owner still held by a slow exit.
    let _ = containment::wait_for_stop_containment(
        scope,
        &state.runtime_sha256,
        deadline,
        &process_ids,
    );
    true
}

#[cfg(test)]
#[path = "managed_resident_handoff_tests.rs"]
mod tests;
