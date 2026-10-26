//! The direct lane's resident connection: which live resident of this
//! runtime, if any, answers a hook without the daemon round trip.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_http::remaining;

/// Below this the round trip cannot finish, so the daemon path starts now
/// rather than after a connect that is already out of time.
const MINIMUM_DIRECT_TIMEOUT: Duration = Duration::from_millis(50);

/// Why a bridge took a hook to the daemon without a resident answer. The
/// bridge names it to the daemon, which counts it beside the hook; nothing
/// decides a hook by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectMiss {
    /// The direct lane is switched off for this bridge.
    Disabled,
    /// The resident is never asked about this event.
    Event,
    /// The bridge could not build the request, such as a guard home or home
    /// outside the resident's reach.
    Request,
    /// No resident state directory, or discovery failed.
    NoState,
    /// No discovered resident runs this caller's runtime.
    NoResident,
    /// The resident's state carries no usable token.
    Token,
    /// Too little time was left to ask.
    Late,
    /// Connecting, the handshake or the exchange failed.
    Send,
    /// The resident deferred the hook; it counts the reason itself.
    Defer,
    /// The resident's reply was not an answer the bridge could use.
    Unanswered,
}

impl DirectMiss {
    /// The code the daemon counts; `[a-z_]` only.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Event => "event",
            Self::Request => "request",
            Self::NoState => "no_state",
            Self::NoResident => "no_resident",
            Self::Token => "token",
            Self::Late => "late",
            Self::Send => "send",
            Self::Defer => "defer",
            Self::Unanswered => "unanswered",
        }
    }
}

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
    send_to_live_resident_reporting(state_base, request, deadline).ok()
}

/// [`send_to_live_resident`], naming why no resident answered.
pub(crate) fn send_to_live_resident_reporting(
    state_base: &Path,
    request: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, DirectMiss> {
    // Discovery checks the directory's privacy; it must already exist.
    if !std::fs::symlink_metadata(state_base).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(DirectMiss::NoState);
    }
    let durable_digest = crate::resident_state::durable_runtime_digest(state_base);
    let states = crate::resident_state::discover_same_executable_states(state_base)
        .map_err(|_| DirectMiss::NoState)?;
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
        let token =
            crate::resident_state::token_from_state(&state).map_err(|_| DirectMiss::Token)?;
        let timeout = remaining(deadline);
        if timeout < MINIMUM_DIRECT_TIMEOUT {
            return Err(DirectMiss::Late);
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
        .map_err(|_| DirectMiss::Send);
    }
    Err(DirectMiss::NoResident)
}
