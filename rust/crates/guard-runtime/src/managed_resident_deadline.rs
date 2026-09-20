//! Preserve a managed request's deadline across lease and return boundaries.
use std::path::Path;
use std::time::Instant;

use super::lease;

fn finish_before_deadline(
    result: Result<Vec<u8>, String>,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    // Expiry can reject a late success, but must preserve an earlier fatal or
    // ambiguous exchange error. It never makes a request safe to replay.
    result.and_then(|response| {
        if Instant::now() >= deadline {
            Err("native_client_deadline_exceeded".to_owned())
        } else {
            Ok(response)
        }
    })
}

pub(crate) fn client_request_at_deadline(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let client_lease = lease::acquire(state_base)?;
    let result = client_request_with_lease(state_base, payload, deadline, &client_lease);
    drop(client_lease);
    #[cfg(test)]
    super::deadline_tests::checkpoint(super::deadline_tests::Stage::LeaseCleanup);
    finish_before_deadline(result, deadline)
}

pub(super) fn client_request_with_lease(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
    client_lease: &lease::ClientLease,
) -> Result<Vec<u8>, String> {
    let result =
        super::client_request_with_lease_inner(state_base, payload, deadline, client_lease);
    #[cfg(test)]
    super::deadline_tests::checkpoint(super::deadline_tests::Stage::Returned);
    finish_before_deadline(result, deadline)
}
