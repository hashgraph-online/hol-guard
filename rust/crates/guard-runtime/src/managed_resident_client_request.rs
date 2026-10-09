#![forbid(unsafe_code)]

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::{containment, handoff, lease, restart_budget, CLIENT_RETRY_DELAY};
use crate::resident_diagnostics::{observe, Phase};
use crate::resident_state::{
    acquire_startup_lock, clear_stale_startup_lock, discover_home_states_prefer, next_generation,
    runtime_digest, state_scope, token_from_state, validate_package_process_identity,
    validate_runtime_process_identity,
};

// Startup may use the caller's remaining budget, never more than nine seconds.
const CLIENT_START_TIMEOUT: Duration = Duration::from_millis(9_000);

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
    for (scope, _digest, state) in discover_home_states_prefer(state_base, Some(preferred_digest))?
    {
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
            digest: (!same_runtime).then_some(&state.runtime_sha256),
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
            // A foreign resident that rejects this runtime's policy snapshot
            // never will admit it; replace it with a resident of our runtime.
            Ok(response)
                if handoff::retire_foreign_resident_rejecting_policy(
                    &scope,
                    &state,
                    &runtime_digest,
                    &response,
                    deadline,
                ) => {}
            Ok(response) => return Ok(Some(response)),
            Err(error)
                if containment::skip_failed_home_state_request(&error, same_runtime, &state) => {}
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
                let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
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
        restart_budget::consume_for_spawn(state_base, &scope)?;
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
    let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
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
#[path = "managed_resident_live_failure_tests.rs"]
mod tests;
