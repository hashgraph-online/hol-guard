#![forbid(unsafe_code)]

#[cfg(unix)]
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Instant;

use crate::resident_state::{
    discover_states, token_from_state, validate_package_process_identity, ResidentState,
};

pub(super) fn is_stale_process_identity_error(error: &str) -> bool {
    #[cfg(windows)]
    {
        matches!(
            error,
            "native_resident_process_identity_unavailable"
                | "native_resident_process_identity_mismatch"
        )
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        false
    }
}

fn try_states_with_state(
    scope: &Path,
    digest: &str,
    payload: &[u8],
    deadline: Instant,
) -> Result<Option<(ResidentState, Vec<u8>)>, String> {
    for state in discover_states(scope, digest)?.into_iter().take(4) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Ok(None);
        }
        if state.transport == "loopback" {
            #[cfg(not(windows))]
            if validate_package_process_identity(state.process_id).is_err() {
                continue;
            }
        }
        let token = token_from_state(&state)?;
        match crate::resident_client::send_request(
            &state.transport,
            &state.endpoint,
            &token,
            payload,
            timeout,
            state.process_id,
        ) {
            Ok(response) => return Ok(Some((state, response))),
            Err(error)
                if error == "native_client_connect_failed"
                    || is_stale_process_identity_error(&error) => {}
            Err(_) => return Err("native_resident_live_request_failed".to_owned()),
        }
    }
    Ok(None)
}

pub(super) fn try_states(
    scope: &Path,
    digest: &str,
    payload: &[u8],
    deadline: Instant,
) -> Result<Option<Vec<u8>>, String> {
    Ok(try_states_with_state(scope, digest, payload, deadline)?.map(|(_, response)| response))
}

#[derive(Clone, Copy)]
struct ShutdownEvidence {
    acknowledged: bool,
    authenticated: bool,
    serving_shutdown: bool,
}

#[derive(Clone, Copy)]
enum LockProbe {
    Free,
    Busy,
    Unverified,
}

impl LockProbe {
    fn is_free(self) -> bool {
        matches!(self, Self::Free)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Busy => "busy",
            Self::Unverified => "unverified",
        }
    }
}

#[cfg(unix)]
fn endpoint_is_contained(state: &ResidentState) -> bool {
    if state.transport != "unix" {
        return true;
    }
    matches!(
        fs::symlink_metadata(Path::new(&state.endpoint)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

#[cfg(not(unix))]
fn endpoint_is_contained(state: &ResidentState) -> bool {
    // Windows residents use an authenticated loopback endpoint. The
    // authenticated stopped acknowledgement and owner-lock probe above are
    // the authoritative listener-containment checks there.
    let _ = state;
    true
}

fn published_endpoint_status(states: &[ResidentState]) -> &'static str {
    if states.is_empty() {
        "unverified"
    } else if states.iter().all(endpoint_is_contained) {
        "absent"
    } else {
        "present"
    }
}

pub(super) fn published_endpoints_are_contained(states: &[ResidentState]) -> bool {
    published_endpoint_status(states) == "absent"
}

fn containment_timeout(
    evidence: ShutdownEvidence,
    generation_present: bool,
    owner_lock: LockProbe,
    marker_lock: LockProbe,
    endpoint: &'static str,
) -> String {
    format!(
        "native_resident_stop_timeout:acknowledged={}:authenticated={}:generation_present={}:owner_lock={}:marker_lock={}:endpoint={}:serving_shutdown={}",
        evidence.acknowledged,
        evidence.authenticated,
        generation_present,
        owner_lock.as_str(),
        marker_lock.as_str(),
        endpoint,
        evidence.serving_shutdown,
    )
}

fn verify_managed_shutdown(
    scope: &Path,
    digest: &str,
    generation: u64,
    deadline: Instant,
    evidence: ShutdownEvidence,
) -> Result<(), String> {
    loop {
        let (owner_lock, marker_lock) = match super::acquire_managed_owner_lock(scope) {
            Ok(lock) => {
                drop(lock);
                (LockProbe::Free, LockProbe::Free)
            }
            Err(error) if error == "native_resident_owner_busy" => {
                (LockProbe::Busy, LockProbe::Unverified)
            }
            Err(error) if error == "native_resident_marker_busy" => {
                (LockProbe::Free, LockProbe::Busy)
            }
            Err(error) => return Err(error),
        };
        let states = discover_states(scope, digest)?;
        let generation_present = states.iter().any(|state| state.generation == generation);
        // The authenticated shutdown acknowledgement is emitted only after
        // the serving listener has stopped and its owner lock is released.
        // Require the persisted generation, both lock probes, and endpoint
        // removal. Recorded serving and supervisor PIDs are informational:
        // either process can be an ephemeral or zombie child after teardown,
        // and neither process can restart a contained server.
        if evidence.acknowledged
            && evidence.authenticated
            && evidence.serving_shutdown
            && owner_lock.is_free()
            && marker_lock.is_free()
            && generation_present
            && published_endpoints_are_contained(&states)
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(containment_timeout(
                evidence,
                generation_present,
                owner_lock,
                marker_lock,
                published_endpoint_status(&states),
            ));
        }
        thread::sleep(super::CLIENT_RETRY_DELAY.min(remaining));
    }
}

pub(crate) fn stop_managed(state_base: &Path) -> Result<(), String> {
    let digest = super::runtime_digest()?;
    let scope = super::state_scope(state_base, &digest)?;
    // Serialize stop with a concurrent starter.  A resident leaves its
    // authenticated generation file behind after shutdown, so the lock plus
    // a successful owner-lock probe lets us distinguish an already-stopped
    // resident from a never-created (or currently-starting) one.
    let mut startup_lock = super::acquire_startup_lock(&scope)?;
    if startup_lock.is_none() && super::clear_stale_startup_lock(&scope, &digest)? {
        startup_lock = super::acquire_startup_lock(&scope)?;
    }
    let _startup_lock =
        startup_lock.ok_or_else(|| "native_resident_stop_unavailable".to_owned())?;
    let request = br#"{"operation":"shutdown","request":{}}"#;
    let stop_deadline = Instant::now() + super::MANAGED_STOP_TIMEOUT;
    let shutdown_response = match try_states_with_state(
        &scope,
        &digest,
        request,
        stop_deadline.min(Instant::now() + super::CLIENT_START_TIMEOUT),
    ) {
        Ok(response) => response,
        // A contained server may close its endpoint immediately after the
        // final response attempt. Verify the persisted generation rather
        // than turning that race into an unverified success.
        Err(error) if error == "native_resident_live_request_failed" => None,
        Err(error) => return Err(error),
    };
    if let Some((state, response)) = shutdown_response {
        let response = crate::strict_json_value(&response)
            .map_err(|_| "native_resident_stop_ack_invalid".to_owned())?;
        if let Some(error) = response.get("error").and_then(serde_json::Value::as_str) {
            if error.starts_with("native_resident_stop_") {
                return Err(error.to_owned());
            }
            return Err("native_resident_stop_ack_invalid".to_owned());
        }
        if matches!(
            response.get("status").and_then(serde_json::Value::as_str),
            Some("stopped" | "stopping")
        ) {
            // The serving process emits this acknowledgement only after its
            // accept loop and owner lock have been released. The external
            // checks below close the remaining supervisor/process race.
            return verify_managed_shutdown(
                &scope,
                &digest,
                state.generation,
                stop_deadline,
                ShutdownEvidence {
                    acknowledged: true,
                    authenticated: true,
                    serving_shutdown: response.get("status").and_then(serde_json::Value::as_str)
                        == Some("stopped"),
                },
            );
        }
        return Err("native_resident_stop_ack_invalid".to_owned());
    }
    // Preserve idempotent cleanup for a previously authenticated resident
    // that has already exited. A missing response is not proof that the
    // resident was contained, so use the same bounded verification path.
    if let Some(state) = discover_states(&scope, &digest)?.first() {
        // A persisted generation with a removed endpoint is the idempotent
        // proof left by a prior authenticated stop acknowledgement.
        return verify_managed_shutdown(
            &scope,
            &digest,
            state.generation,
            stop_deadline,
            ShutdownEvidence {
                acknowledged: true,
                authenticated: true,
                serving_shutdown: true,
            },
        );
    }
    Err("native_resident_stop_unavailable".to_owned())
}
