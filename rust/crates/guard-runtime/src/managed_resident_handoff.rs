#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use super::{containment, lease, MANAGED_STOP_TIMEOUT};
use crate::resident_state::{token_from_state, ResidentState};

/// Bounds how long the lease directory stays locked for the shutdown, well
/// under the lease expiry so concurrent clients' heartbeats stay fresh.
const HANDOFF_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// A side-by-side update leaves the previous runtime's resident running after
/// its clients exit. Older runtimes count every client lease in the home, so
/// newer clients keep that resident alive while it holds the home-wide owner
/// lock and can never acknowledge their policy.
///
/// Every managed client holds a lease of its runtime while it uses a
/// resident, so a foreign resident without a live lease of its own digest
/// serves nobody. Stop it through its authenticated shutdown and wait for its
/// processes to exit. Returns false when the resident is in use, the shutdown
/// was not acknowledged or the resident did not exit, in which case the
/// caller keeps treating it as before and fails closed.
pub(super) fn retire_orphaned_foreign_resident(
    state_base: &Path,
    scope: &Path,
    state: &ResidentState,
    runtime_digest: &str,
    deadline: Instant,
) -> bool {
    if state.runtime_sha256 == runtime_digest {
        return false;
    }
    let deadline = deadline.min(Instant::now() + MANAGED_STOP_TIMEOUT);
    let process_ids = containment::state_process_identities(std::slice::from_ref(state));
    // Hold the lease directory lock from the final lease check through the
    // shutdown so no client of the older runtime can start using it between.
    let acknowledged = lease::unless_live(state_base, &state.runtime_sha256, || {
        request_shutdown(
            state,
            deadline.min(Instant::now() + HANDOFF_SHUTDOWN_TIMEOUT),
        )
    });
    acknowledged == Some(true)
        && wait_for_resident_stop_containment(scope, state, deadline, &process_ids).is_ok()
}

/// Two current installs (for example a desktop app and a package install)
/// can share one home. Whichever starts the managed resident first owns the
/// home-wide lock, so the other install's policy publisher reaches a resident
/// that admits only snapshots bound to its own runtime. Every push is then
/// rejected and hooks fail closed on a stale snapshot indefinitely.
///
/// The resident's rejection is the authoritative signal: it never admits this
/// runtime's policy. Stop it even while clients of its runtime still hold
/// leases, so the publisher's caller can start a resident of its own runtime.
/// Those clients keep working because they already reach a resident of
/// another runtime through the same discovery path. Returns false when the
/// resident is ours, the shutdown was not acknowledged or the resident did
/// not exit, in which case the caller returns the rejection unchanged.
pub(super) fn retire_foreign_resident_rejecting_policy(
    scope: &Path,
    state: &ResidentState,
    runtime_digest: &str,
    response: &[u8],
    deadline: Instant,
) -> bool {
    if state.runtime_sha256 == runtime_digest || !rejects_runtime_policy(response) {
        return false;
    }
    let deadline = deadline.min(Instant::now() + MANAGED_STOP_TIMEOUT);
    let process_ids = containment::state_process_identities(std::slice::from_ref(state));
    request_shutdown(
        state,
        deadline.min(Instant::now() + HANDOFF_SHUTDOWN_TIMEOUT),
    ) && wait_for_resident_stop_containment(scope, state, deadline, &process_ids).is_ok()
}

fn rejects_runtime_policy(response: &[u8]) -> bool {
    crate::strict_json_value(response).is_ok_and(|response| {
        response.get("error").and_then(serde_json::Value::as_str)
            == Some("snapshot_runtime_identity_mismatch")
    })
}

/// Contain only the stopped resident. A replacement that a client of the
/// same runtime starts after the lease lock is released has a different
/// identity and is left alone.
fn wait_for_resident_stop_containment(
    scope: &Path,
    resident: &ResidentState,
    deadline: Instant,
    known_processes: &[containment::ManagedProcessIdentity],
) -> Result<(), String> {
    containment::wait_for_matching_stop_containment(
        scope,
        &resident.runtime_sha256,
        deadline,
        known_processes,
        |state| {
            state.generation == resident.generation
                && state.process_id == resident.process_id
                && state.process_start_marker == resident.process_start_marker
        },
    )
}

fn request_shutdown(state: &ResidentState, deadline: Instant) -> bool {
    let Ok(token) = token_from_state(state) else {
        return false;
    };
    let identity = crate::resident_client::ExpectedProcessIdentity {
        process_id: state.process_id,
        start_marker: &state.process_start_marker,
        digest: Some(&state.runtime_sha256),
    };
    crate::resident_client::send_request_for_digest(
        &state.transport,
        &state.endpoint,
        &token,
        br#"{"operation":"shutdown","request":{}}"#,
        deadline.saturating_duration_since(Instant::now()),
        &identity,
    )
    .is_ok_and(|response| shutdown_acknowledged(&response))
}

fn shutdown_acknowledged(response: &[u8]) -> bool {
    crate::strict_json_value(response).is_ok_and(|response| {
        response.get("error").is_none()
            && matches!(
                response.get("status").and_then(serde_json::Value::as_str),
                Some("stopped" | "stopping")
            )
    })
}

#[cfg(test)]
#[path = "managed_resident_handoff_tests.rs"]
mod tests;
