//! Preserve the same authority subjects through the actual hook response boundary.
use crate::policy_store::ClientAuthorityObservation;
use crate::resident_client::ResidentClientError;
use crate::resident_protocol::{decode_resident_request, ResidentRequestV1};
use std::path::Path;
use std::time::{Duration, Instant};

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err("native_client_deadline_exceeded".to_owned())
    } else {
        Ok(remaining)
    }
}

// Outer failures are terminal: a post-send refusal must never enter transport retry logic.
pub(crate) fn request<F>(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
    send: F,
) -> Result<Result<Vec<u8>, ResidentClientError>, String>
where
    F: FnOnce(Duration) -> Result<Vec<u8>, ResidentClientError>,
{
    remaining(deadline)?;
    let hook = matches!(
        decode_resident_request(payload)?,
        ResidentRequestV1::Edge(_)
    );
    if !hook {
        return Ok(send(remaining(deadline)?));
    }
    let before = ClientAuthorityObservation::capture(state_base)?;
    let response = match send(remaining(deadline)?) {
        Ok(response) => response,
        Err(error) => return Ok(Err(error)),
    };
    remaining(deadline)?;
    let after = ClientAuthorityObservation::capture(state_base)?;
    remaining(deadline)?;
    if before != after {
        return Err("native_policy_snapshot_context_mismatch".to_owned());
    }
    Ok(Ok(response))
}
