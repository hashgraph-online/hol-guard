//! The direct lane's resident connection: which live resident of this
//! runtime, if any, answers a hook without the daemon round trip.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_http::remaining;

/// Below this the round trip cannot finish, so the daemon path starts now
/// rather than after a connect that is already out of time.
const MINIMUM_DIRECT_TIMEOUT: Duration = Duration::from_millis(50);

/// Send the request to a live resident that runs this caller's own runtime.
///
/// The same steps serve every platform. Discovery reads only owner-only
/// state, the resident must run this executable path or carry the digest
/// this executable's durable copy is published under, it must still carry the
/// start marker its state records, and the client checks that identity again
/// around the connect before the token handshake. A Windows resident
/// publishes a loopback endpoint; a unix resident may publish either.
pub(crate) fn send_to_live_resident(
    state_base: &Path,
    request: &[u8],
    deadline: Instant,
) -> Option<Vec<u8>> {
    // Discovery checks the directory's privacy; it must already exist.
    if !std::fs::symlink_metadata(state_base).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    let durable_digest = crate::resident_state::durable_runtime_digest(state_base);
    let states = crate::resident_state::discover_same_executable_states(state_base).ok()?;
    for (_scope, _digest, state) in states {
        if crate::resident_state::validate_direct_lane_process_identity(
            state.process_id,
            &state.process_start_marker,
            &state.runtime_sha256,
            durable_digest.as_deref(),
        )
        .is_err()
        {
            continue;
        }
        let token = crate::resident_state::token_from_state(&state).ok()?;
        let timeout = remaining(deadline);
        if timeout < MINIMUM_DIRECT_TIMEOUT {
            return None;
        }
        let identity = crate::resident_client::ExpectedProcessIdentity {
            process_id: state.process_id,
            start_marker: &state.process_start_marker,
            runtime: crate::resident_client::ExpectedRuntime::for_direct_lane(
                &state.runtime_sha256,
                durable_digest.as_deref(),
            ),
        };
        // One live resident serves a home; any failure goes to the daemon.
        return crate::resident_client::send_request_for_digest_detailed(
            &state.transport,
            &state.endpoint,
            &token,
            request,
            timeout,
            &identity,
        )
        .ok();
    }
    None
}
