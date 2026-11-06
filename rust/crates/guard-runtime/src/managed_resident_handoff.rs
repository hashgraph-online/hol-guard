#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use super::{containment, lease, MANAGED_STOP_TIMEOUT};
use crate::resident_diagnostics::note;
use crate::resident_state::{token_from_state, ResidentState};

/// Bounds how long the lease directory stays locked for the shutdown, well
/// under the lease expiry so concurrent clients' heartbeats stay fresh.
const HANDOFF_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// A handoff asks a resident to make way for another runtime; the resident
/// may refuse it (see `refuses_shutdown`). Explicit stops always succeed.
const HANDOFF_SHUTDOWN_REQUEST: &[u8] =
    br#"{"operation":"shutdown","request":{"intent":"handoff"}}"#;
pub(super) const STOP_SHUTDOWN_REQUEST: &[u8] =
    br#"{"operation":"shutdown","request":{"intent":"stop"}}"#;
/// Answered instead of stopping when a handoff would take the resident from
/// live clients of the runtime the home publishes for.
pub(crate) const SHUTDOWN_REFUSED_IN_USE: &str = "native_resident_in_use";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShutdownIntent {
    /// An operator or update stop: always honoured.
    Stop,
    /// Another client making way for its runtime. Older clients send a bare
    /// request, which means the same.
    Handoff,
}

fn shutdown_intent(request: &serde_json::Value) -> ShutdownIntent {
    match request.get("intent").and_then(serde_json::Value::as_str) {
        Some("stop") => ShutdownIntent::Stop,
        _ => ShutdownIntent::Handoff,
    }
}

/// Two installs can share one home: one whose publisher binds every snapshot
/// to its runtime, and an older one whose hooks still run. The older client
/// reaches the publisher's resident, has its request rejected and asks that
/// resident to shut down while its own clients still use it; its own
/// resident then exits at once on the snapshot bound to the other runtime,
/// and the two restart each other until a restart budget opens. Shipped
/// clients cannot be changed, so the resident refuses that handoff.
///
/// Refuse only a handoff, only while the latest published snapshot is bound
/// to this resident's runtime, and only while a client of this runtime
/// provably holds a live lease. Any doubt stops as before, so a resident is
/// never left unstoppable: a resident the home no longer publishes for still
/// makes way, and so does one nothing uses.
pub(crate) fn refuses_shutdown(
    request: &serde_json::Value,
    policy_store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> bool {
    policy_store.is_some_and(|store| {
        refuses_handoff(
            request,
            store.state_base(),
            store.runtime_identity(),
            || store.published_runtime_identity(),
        )
    })
}

/// Answers an authenticated shutdown: refuses a handoff `refuses_shutdown`
/// declines with `SHUTDOWN_REFUSED_IN_USE`, otherwise starts the stop.
pub(crate) fn answer_shutdown(
    request: &serde_json::Value,
    policy_store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<serde_json::Value, String> {
    if refuses_shutdown(request, policy_store) {
        return Err(SHUTDOWN_REFUSED_IN_USE.to_owned());
    }
    super::request_shutdown();
    Ok(serde_json::json!({"status": "stopping"}))
}

/// `published_runtime` yields the runtime the publisher's latest snapshot is
/// bound to, or `None` when that cannot be read. It runs only for a handoff,
/// and the lease directory is probed only when it names this runtime.
fn refuses_handoff(
    request: &serde_json::Value,
    state_base: &Path,
    own_digest: &str,
    published_runtime: impl FnOnce() -> Option<String>,
) -> bool {
    shutdown_intent(request) == ShutdownIntent::Handoff
        && published_runtime().is_some_and(|runtime| runtime == own_digest)
        && lease::definitely_live(state_base, own_digest)
}

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
/// The same holds for a request shape the foreign resident does not support:
/// a capability bump adds fields its strict typed parser denies, so it answers
/// `native_request_schema_unsupported`. That code is emitted only when typed
/// request deserialization fails; transient failures and other errors, which
/// the safe-error mapping folds into `native_request_invalid_json`, never
/// retire a resident.
///
/// The resident's rejection is the authoritative signal: it never admits this
/// runtime's policy or request. Stop it even while clients of its runtime
/// still hold leases, so the caller can start a resident of its own runtime.
/// Those clients keep working because they already reach a resident of
/// another runtime through the same discovery path. Returns false when the
/// resident is ours, the shutdown was not acknowledged or the resident did
/// not exit, in which case the caller returns the rejection unchanged. A
/// genuinely malformed request is answered the same way by our own resident,
/// which is never retired, so it still fails closed. A resident the home
/// still publishes for refuses this handoff while its clients are live
/// (`native_resident_in_use`), which is likewise not an acknowledgement.
pub(super) fn retire_foreign_resident_rejecting_request(
    scope: &Path,
    state: &ResidentState,
    runtime_digest: &str,
    response: &[u8],
    deadline: Instant,
) -> bool {
    if state.runtime_sha256 == runtime_digest || !rejects_runtime_request(response) {
        return false;
    }
    // Record the rejection before the retirement attempt, which may fail.
    note("client_state_foreign_rejection_seen", 1);
    let deadline = deadline.min(Instant::now() + MANAGED_STOP_TIMEOUT);
    let process_ids = containment::state_process_identities(std::slice::from_ref(state));
    request_shutdown(
        state,
        deadline.min(Instant::now() + HANDOFF_SHUTDOWN_TIMEOUT),
    ) && wait_for_resident_stop_containment(scope, state, deadline, &process_ids).is_ok()
}

fn rejects_runtime_request(response: &[u8]) -> bool {
    crate::strict_json_value(response).is_ok_and(|response| {
        matches!(
            response.get("error").and_then(serde_json::Value::as_str),
            Some("snapshot_runtime_identity_mismatch" | "native_request_schema_unsupported")
        )
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
        runtime: crate::resident_client::ExpectedRuntime::Digest(&state.runtime_sha256),
    };
    crate::resident_client::send_request_for_digest(
        &state.transport,
        &state.endpoint,
        &token,
        HANDOFF_SHUTDOWN_REQUEST,
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
