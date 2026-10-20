#![forbid(unsafe_code)]

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::{containment, handoff, lease, restart_budget, CLIENT_RETRY_DELAY};
use crate::resident_diagnostics::{note, observe, Phase};
use crate::resident_state::{
    acquire_startup_lock, clear_stale_startup_lock, discover_home_states_prefer, next_generation,
    runtime_digest, state_scope, token_from_state, validate_package_process_identity,
    validate_runtime_process_identity,
};

// Ordinary startup may use the caller's remaining budget, never more than nine
// seconds. Daemon lifecycle cold start may use the caller's budget up to the
// thirty-second ceiling in the parent module.
const CLIENT_START_TIMEOUT: Duration = Duration::from_millis(9_000);
const DAEMON_LIFECYCLE_START_TIMEOUT: Duration =
    Duration::from_millis(super::DAEMON_LIFECYCLE_TIMEOUT_CEILING_MS);

fn startup_limit(payload: &[u8]) -> Duration {
    let value = crate::strict_json_value(payload).ok();
    match value
        .as_ref()
        .and_then(|value| value.get("operation")?.as_str())
    {
        Some("daemon_lifecycle_decide") => DAEMON_LIFECYCLE_START_TIMEOUT,
        _ => CLIENT_START_TIMEOUT,
    }
}

fn try_live_or_restart(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
    preferred_digest: &str,
    last_failure: &mut Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    retain_live_failure(
        try_home_states(state_base, payload, deadline, preferred_digest),
        last_failure,
    )
}

fn retain_live_failure(
    result: Result<Option<Vec<u8>>, String>,
    last_failure: &mut Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    match result {
        Err(error) if error.starts_with("native_resident_live_request_failed:") => {
            *last_failure = Some(error);
            Ok(None)
        }
        other => other,
    }
}

fn try_home_states(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
    preferred_digest: &str,
) -> Result<Option<Vec<u8>>, String> {
    let runtime_digest = runtime_digest()?;
    let states = discover_home_states_prefer(state_base, Some(preferred_digest))?;
    note("client_states", states.len());
    for (scope, _digest, state) in states {
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Ok(None);
        }
        // Hand the home over from an older resident nothing of its runtime
        // still uses; this client then starts its own resident.
        if handoff::retire_orphaned_foreign_resident(
            state_base,
            &scope,
            &state,
            &runtime_digest,
            deadline,
        ) {
            note("client_state_foreign_retired", 1);
            continue;
        }
        let same_runtime = runtime_digest == state.runtime_sha256;
        if observe(Phase::ClientIdentity, || {
            if same_runtime {
                validate_package_process_identity(state.process_id, &state.process_start_marker)
            } else {
                validate_runtime_process_identity(
                    state.process_id,
                    &state.process_start_marker,
                    &state.runtime_sha256,
                )
            }
        })
        .is_err()
        {
            continue;
        }
        let token = token_from_state(&state)?;
        let identity = crate::resident_client::ExpectedProcessIdentity {
            process_id: state.process_id,
            start_marker: &state.process_start_marker,
            runtime: if same_runtime {
                crate::resident_client::ExpectedRuntime::Package
            } else {
                crate::resident_client::ExpectedRuntime::Digest(&state.runtime_sha256)
            },
        };
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Ok(None);
        }
        match crate::resident_client::send_request_for_digest_detailed(
            &state.transport,
            &state.endpoint,
            &token,
            payload,
            timeout,
            &identity,
        ) {
            // A foreign resident that rejects this runtime's policy snapshot or
            // a request it predates never will admit it; replace it with a
            // resident of our runtime.
            Ok(response)
                if handoff::retire_foreign_resident_rejecting_request(
                    &scope,
                    &state,
                    &runtime_digest,
                    &response,
                    deadline,
                ) =>
            {
                note("client_state_foreign_rejected", 1);
            }
            Ok(response) => return Ok(Some(response)),
            Err(error)
                if containment::skip_failed_home_state_request(&error, same_runtime, &state) =>
            {
                note("client_state_request_skipped", 1);
            }
            Err(error) => {
                let code = if error.code.len() <= 96
                    && !error.code.is_empty()
                    && error.code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }) {
                    error.code.as_str()
                } else {
                    "native_client_request_failed"
                };
                return Err(format!("native_resident_live_request_failed:{code}"));
            }
        }
    }
    Ok(None)
}

/// Whether discovery finds a live resident that runs `digest`.
fn live_resident_of_runtime(state_base: &Path, digest: &str) -> bool {
    // An unreadable state keeps the old behaviour of spending the budget.
    // Discovery also returns this runtime's states whose process has exited,
    // so a state counts as dead only when its process is provably gone or its
    // PID now belongs to a process with another start marker. A process that
    // cannot be inspected still counts as live.
    match discover_home_states_prefer(state_base, Some(digest)) {
        Ok(states) => states
            .iter()
            .any(|(_, _, state)| state.runtime_sha256 == digest && state_may_be_live(state)),
        Err(_) => true,
    }
}

fn state_may_be_live(state: &crate::resident_state::ResidentState) -> bool {
    use crate::resident_state::{process_is_definitively_gone, process_start_marker};
    if process_is_definitively_gone(state.process_id).unwrap_or(false) {
        return false;
    }
    process_start_marker(state.process_id).map_or(true, |marker| {
        crate::constant_time_eq(marker.as_bytes(), state.process_start_marker.as_bytes())
    })
}

pub(super) fn client_request_with_deadline(
    state_base: &Path,
    payload: &[u8],
    overall_deadline: Instant,
    client_lease: &lease::ClientLease,
) -> Result<Vec<u8>, String> {
    let mut last_failure = None;
    client_request_with_deadline_inner(
        state_base,
        payload,
        overall_deadline,
        client_lease,
        &mut last_failure,
    )
    .inspect_err(|_| {
        if let Some(cause) = last_failure.as_deref() {
            // Keep the finite wire error vocabulary unchanged. The native CLI
            // exposes this bounded diagnostic separately on stderr, followed
            // by the original registered failure from main(). No request data
            // or filesystem paths are included.
            eprintln!("native_resident_recovery_previous_failure={cause}");
        }
    })
}

fn client_request_with_deadline_inner(
    state_base: &Path,
    payload: &[u8],
    overall_deadline: Instant,
    _client_lease: &lease::ClientLease,
    last_failure: &mut Option<String>,
) -> Result<Vec<u8>, String> {
    // Keep the caller's budget intact. Windows spawn already has
    // CLIENT_START_TIMEOUT; shrinking every live request by 300ms makes the
    // 250ms command-model SLO miss the ready serve entirely.
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let (digest, _update_lock, scope) = observe(Phase::ClientPrepare, || -> Result<_, String> {
        let digest = runtime_digest()?;
        let update_lock = crate::resident_update_lock::acquire_shared(state_base, &digest)?;
        let scope = state_scope(state_base, &digest)?;
        Ok((digest, update_lock, scope))
    })?;
    if let Some(response) = observe(Phase::ClientDiscovery, || {
        try_live_or_restart(state_base, payload, overall_deadline, &digest, last_failure)
    })? {
        return Ok(response);
    }
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    // Older per-digest launchers left their startup marker in the runtime
    // scope.  Retire only an authenticated stale marker before taking the
    // home-wide lock; a live marker remains an active startup signal.
    let mut lock = observe(Phase::ClientStartupLock, || -> Result<_, String> {
        let _ = clear_stale_startup_lock(&scope, &digest)?;
        let mut lock = acquire_startup_lock(state_base)?;
        if lock.is_none() && clear_stale_startup_lock(state_base, &digest)? {
            lock = acquire_startup_lock(state_base)?;
        }
        Ok(lock)
    })?;
    if lock.is_none() {
        let response = observe(
            Phase::ClientStartupWait,
            || -> Result<Option<Vec<u8>>, String> {
                let deadline = overall_deadline.min(Instant::now() + startup_limit(payload));
                while Instant::now() < deadline {
                    if let Some(response) = try_live_or_restart(
                        state_base,
                        payload,
                        overall_deadline,
                        &digest,
                        last_failure,
                    )? {
                        return Ok(Some(response));
                    }
                    thread::sleep(
                        CLIENT_RETRY_DELAY.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                if clear_stale_startup_lock(state_base, &digest)? {
                    lock = acquire_startup_lock(state_base)?;
                }
                Ok(None)
            },
        )?;
        if let Some(response) = response {
            return Ok(response);
        }
    }
    let _startup_lock = lock.ok_or_else(|| "native_resident_start_in_progress".to_owned())?;
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    if let Some(response) = observe(Phase::ClientDiscovery, || {
        try_live_or_restart(state_base, payload, overall_deadline, &digest, last_failure)
    })? {
        return Ok(response);
    }
    let (generation, token, mut spawned) = observe(Phase::ClientSpawn, || -> Result<_, String> {
        // A resident from another Guard install holds the home-wide owner
        // lock. A spawn here could only fail on that lock, so name the owner
        // instead of spending the restart budget on it. A live resident of
        // this runtime holding the lock is unhealthy, not foreign: it keeps
        // spending the budget so the restart circuit still opens.
        match super::acquire_managed_owner_lock(state_base) {
            Err(error)
                if error == "native_resident_owner_busy"
                    && !live_resident_of_runtime(state_base, &digest) =>
            {
                return Err(error)
            }
            probe => drop(probe),
        }
        restart_budget::consume_for_spawn(state_base, &scope, overall_deadline)?;
        let generation = next_generation(&scope, &digest)?;
        let mut token = [0u8; crate::AUTH_TOKEN_BYTES];
        getrandom::fill(&mut token).map_err(|_| "native_client_random_failed".to_owned())?;
        let spawned = containment::spawn_managed_for_owner(
            state_base,
            generation,
            &digest,
            &token,
            std::process::id(),
            overall_deadline,
        )?;
        Ok((generation, token, spawned))
    })?;
    let deadline = overall_deadline.min(Instant::now() + startup_limit(payload));
    let request_result = observe(Phase::ClientSpawnWait, || loop {
        if Instant::now() >= deadline {
            break Err("native_resident_start_timeout".to_owned());
        }
        match try_live_or_restart(state_base, payload, overall_deadline, &digest, last_failure) {
            Ok(Some(response)) => break Ok(response),
            Ok(None) => {}
            Err(error) => break Err(error),
        }
        thread::sleep(CLIENT_RETRY_DELAY.min(deadline.saturating_duration_since(Instant::now())));
    });
    match request_result {
        Ok(response) => Ok(response),
        Err(error) => {
            // Cleanup retries share the request deadline. A failed containment
            // check must remain visible rather than be hidden by the request error.
            containment::abort_spawned_managed(
                &mut spawned,
                &scope,
                &digest,
                generation,
                &token,
                overall_deadline,
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod startup_limit_tests {
    use super::startup_limit;
    use std::time::Duration;

    #[test]
    fn daemon_lifecycle_startup_keeps_the_cold_start_budget() {
        assert_eq!(
            startup_limit(br#"{"operation":"daemon_lifecycle_decide"}"#),
            Duration::from_secs(30)
        );
        assert_eq!(
            startup_limit(br#"{"operation":"prompt_analyze","deadline_budget_ms":30000}"#),
            Duration::from_secs(9)
        );
        assert_eq!(startup_limit(br"{}"), Duration::from_secs(9));
    }
}

#[cfg(test)]
#[path = "managed_resident_live_failure_tests.rs"]
mod tests;
