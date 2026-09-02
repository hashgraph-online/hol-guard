#![forbid(unsafe_code)]

#[cfg(not(windows))]
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[path = "managed_resident_client_stream.rs"]
mod client_stream;
#[path = "managed_resident_containment.rs"]
mod containment;
#[path = "managed_resident_lease.rs"]
mod lease;
#[path = "managed_resident_transport.rs"]
mod managed_resident_transport;
#[cfg(windows)]
#[path = "managed_resident_windows.rs"]
mod managed_resident_windows;
#[path = "managed_resident_owner_lock.rs"]
mod owner_lock;
#[path = "resident_state_retirement.rs"]
mod resident_state_retirement;
#[path = "resident_restart_budget.rs"]
mod restart_budget;

#[cfg(all(test, unix))]
const MANAGED_OWNER_LOCK_FILE_NAME: &str = owner_lock::MANAGED_OWNER_LOCK_FILE_NAME;

use crate::resident_state::{
    acquire_startup_lock, clear_stale_startup_lock, discover_home_states_prefer, next_generation,
    process_start_marker, runtime_digest, state_scope, token_from_state,
    validate_package_process_identity, validate_runtime_process_identity,
};

pub(crate) fn client_stream(state_base: &Path) -> Result<(), String> {
    client_stream::run(state_base)
}

const CLIENT_START_TIMEOUT: Duration = Duration::from_millis(600);
const CLIENT_RETRY_DELAY: Duration = Duration::from_millis(5);
const MANAGED_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MANAGED_STOP_TIMEOUT: Duration = Duration::from_secs(2);
static MANAGED_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn acquire_managed_owner_lock(scope: &Path) -> Result<owner_lock::ManagedOwnerLock, String> {
    owner_lock::acquire(scope)
}

pub(crate) fn request_shutdown() {
    MANAGED_SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

fn shutdown_requested() -> bool {
    MANAGED_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

fn managed_owner_liveness(
    state_base: &Path,
    owner_process_id: u32,
    owner_start_marker: String,
) -> Arc<AtomicBool> {
    let alive = Arc::new(AtomicBool::new(true));
    let watcher_alive = Arc::clone(&alive);
    let base = state_base.to_owned();
    thread::spawn(move || {
        let mut no_lease_since = None;
        loop {
            if shutdown_requested() {
                watcher_alive.store(false, Ordering::Release);
                break;
            }
            let owner_alive = process_start_marker(owner_process_id)
                .is_ok_and(|actual| actual == owner_start_marker);
            if owner_alive || lease::any_live_for_home(&base) {
                no_lease_since = None;
            } else {
                let started = no_lease_since.get_or_insert_with(Instant::now);
                if started.elapsed() >= lease::LEASE_EXPIRY {
                    watcher_alive.store(false, Ordering::Release);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    alive
}

fn combine_liveness(
    state_base: &Path,
    owner_process_id: u32,
    owner_start_marker: String,
) -> Arc<AtomicBool> {
    let owner_alive = managed_owner_liveness(state_base, owner_process_id, owner_start_marker);
    let supervisor_alive = crate::resident_stdin_liveness();
    let combined = Arc::new(AtomicBool::new(true));
    let combined_watcher = Arc::clone(&combined);
    thread::spawn(move || {
        while owner_alive.load(Ordering::Acquire) && supervisor_alive.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(25));
        }
        combined_watcher.store(false, Ordering::Release);
    });
    combined
}

fn is_stale_process_identity_error(error: &str) -> bool {
    matches!(
        error,
        "native_resident_process_identity_unavailable"
            | "native_resident_process_identity_mismatch"
    )
}

fn try_home_states(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
    preferred_digest: &str,
) -> Result<Option<Vec<u8>>, String> {
    let runtime_digest = runtime_digest()?;
    for (_scope, _digest, state) in discover_home_states_prefer(state_base, Some(preferred_digest))?
    {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Ok(None);
        }
        let same_runtime = runtime_digest == state.runtime_sha256;
        if (same_runtime
            && validate_package_process_identity(state.process_id, &state.process_start_marker)
                .is_err())
            || (!same_runtime
                && validate_runtime_process_identity(
                    state.process_id,
                    &state.process_start_marker,
                    &state.runtime_sha256,
                )
                .is_err())
        {
            continue;
        }
        let token = token_from_state(&state)?;
        let identity = crate::resident_client::ExpectedProcessIdentity {
            process_id: state.process_id,
            start_marker: &state.process_start_marker,
            digest: (!same_runtime).then_some(&state.runtime_sha256),
        };
        match crate::resident_client::send_request_for_digest(
            &state.transport,
            &state.endpoint,
            &token,
            payload,
            timeout,
            &identity,
        ) {
            Ok(response) => return Ok(Some(response)),
            Err(error)
                if error == "native_client_connect_failed"
                    || is_stale_process_identity_error(&error) => {}
            Err(_) => return Err("native_resident_live_request_failed".to_owned()),
        }
    }
    Ok(None)
}

pub(crate) fn client_request(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let client_lease = lease::acquire(state_base)?;
    client_request_with_lease(state_base, payload, timeout, &client_lease)
}

fn client_request_with_lease(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
    _client_lease: &lease::ClientLease,
) -> Result<Vec<u8>, String> {
    if timeout.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let overall_deadline = Instant::now() + timeout;
    let digest = runtime_digest()?;
    let scope = state_scope(state_base, &digest)?;
    if let Some(response) = try_home_states(state_base, payload, overall_deadline, &digest)? {
        return Ok(response);
    }
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    // Older per-digest launchers left their startup marker in the runtime
    // scope.  Retire only an authenticated stale marker before taking the
    // home-wide lock; a live marker remains an active startup signal.
    let _ = clear_stale_startup_lock(&scope, &digest)?;
    let mut lock = acquire_startup_lock(state_base)?;
    if lock.is_none() && clear_stale_startup_lock(state_base, &digest)? {
        lock = acquire_startup_lock(state_base)?;
    }
    if lock.is_none() {
        let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
        while Instant::now() < deadline {
            if let Some(response) = try_home_states(state_base, payload, overall_deadline, &digest)?
            {
                return Ok(response);
            }
            thread::sleep(CLIENT_RETRY_DELAY);
        }
        if clear_stale_startup_lock(state_base, &digest)? {
            lock = acquire_startup_lock(state_base)?;
        }
    }
    let _startup_lock = lock.ok_or_else(|| "native_resident_start_in_progress".to_owned())?;
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    if let Some(response) = try_home_states(state_base, payload, overall_deadline, &digest)? {
        return Ok(response);
    }
    restart_budget::consume(&scope)?;
    let generation = next_generation(&scope, &digest)?;
    let mut token = [0u8; crate::AUTH_TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|_| "native_client_random_failed".to_owned())?;
    let mut spawned = containment::spawn_managed_for_owner(
        state_base,
        generation,
        &digest,
        &token,
        std::process::id(),
    )?;
    let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
    let request_result = loop {
        if Instant::now() >= deadline {
            break Ok(None);
        }
        match try_home_states(state_base, payload, overall_deadline, &digest) {
            Ok(Some(response)) => break Ok(Some(response)),
            Ok(None) => {}
            Err(error) => break Err(error),
        }
        thread::sleep(CLIENT_RETRY_DELAY);
    };
    match request_result {
        Ok(Some(response)) => Ok(response),
        Ok(None) => {
            containment::contain_spawned_managed(
                &mut spawned,
                &scope,
                &digest,
                generation,
                &token,
            )?;
            Err("native_resident_start_timeout".to_owned())
        }
        Err(error) => {
            containment::contain_spawned_managed(
                &mut spawned,
                &scope,
                &digest,
                generation,
                &token,
            )?;
            Err(error)
        }
    }
}

pub(crate) fn stop_managed(state_base: &Path) -> Result<(), String> {
    // Materialize the current runtime scope even when no resident state is
    // present.  This keeps the stop command's authenticated, private-home
    // contract deterministic for callers that use it to initialize a fresh
    // scope before publishing test or recovery state.
    let digest = runtime_digest()?;
    let _ = state_scope(state_base, &digest)?;
    let request = br#"{"operation":"shutdown","request":{}}"#;
    let deadline = Instant::now() + MANAGED_STOP_TIMEOUT;
    let Some((scope, digest, state)) = discover_home_states_prefer(state_base, Some(&digest))?
        .into_iter()
        .next()
    else {
        return Err("native_resident_stop_unavailable".to_owned());
    };
    let process_ids = containment::state_process_identities(std::slice::from_ref(&state));
    let token = token_from_state(&state)?;
    let identity = crate::resident_client::ExpectedProcessIdentity {
        process_id: state.process_id,
        start_marker: &state.process_start_marker,
        digest: Some(&state.runtime_sha256),
    };
    if crate::resident_client::send_request_for_digest(
        &state.transport,
        &state.endpoint,
        &token,
        request,
        deadline.saturating_duration_since(Instant::now()),
        &identity,
    )
    .is_ok()
    {
        return containment::wait_for_stop_containment(&scope, &digest, deadline, &process_ids);
    }
    Err("native_resident_stop_unavailable".to_owned())
}

pub(crate) fn serve_managed(
    state_base: &Path,
    generation: u64,
    owner_process_id: u32,
    expected_digest: &str,
) -> Result<(), String> {
    MANAGED_SHUTDOWN_REQUESTED.store(false, Ordering::Release);
    if generation == 0 || owner_process_id == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let owner_start_marker = process_start_marker(owner_process_id)?;
    let scope = state_scope(state_base, expected_digest)?;
    let _owner_lock = acquire_managed_owner_lock(state_base)?;
    let policy_store = std::sync::Arc::new(
        crate::policy_store::PolicySnapshotStore::new_with_resident_generation(
            state_base,
            expected_digest,
            generation,
        )?,
    );
    let token = crate::read_resident_auth_token()?;
    let owner_alive = combine_liveness(state_base, owner_process_id, owner_start_marker);
    if cfg!(unix) {
        managed_resident_transport::serve_unix_managed(
            &scope,
            policy_store,
            generation,
            owner_process_id,
            expected_digest,
            token,
            owner_alive,
        )
    } else {
        managed_resident_transport::serve_loopback_managed(
            &scope,
            policy_store,
            generation,
            owner_process_id,
            expected_digest,
            token,
            owner_alive,
        )
    }
}

pub(crate) fn supervise_managed(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
) -> Result<(), String> {
    let owner_process_id =
        crate::resident_state::parent_process_id().unwrap_or_else(std::process::id);
    supervise_managed_for_owner(state_base, generation, expected_digest, owner_process_id)
}

pub(crate) fn supervise_managed_for_owner(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
    owner_process_id: u32,
) -> Result<(), String> {
    if generation == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let token = crate::read_resident_auth_token()?;
    #[cfg(windows)]
    return managed_resident_windows::supervise_managed(
        state_base,
        generation,
        expected_digest,
        owner_process_id,
        &token,
    );
    #[cfg(not(windows))]
    {
        let executable = std::env::current_exe()
            .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
        let mut child = Command::new(executable);
        child
            .arg("serve-managed")
            .arg("--state-dir")
            .arg(state_base)
            .arg("--generation")
            .arg(generation.to_string())
            .arg("--owner-process-id")
            .arg(std::process::id().to_string())
            .arg("--runtime-sha256")
            .arg(expected_digest)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The supervisor was launched in its own process group by
        // spawn_managed_for_owner. Leave the serving child in that inherited
        // group so startup timeout containment addresses both processes as
        // one authenticated unit.
        let mut child = child
            .spawn()
            .map_err(|_| "native_resident_spawn_failed".to_owned())?;
        let mut liveness_writer = child
            .stdin
            .take()
            .ok_or_else(|| "native_resident_spawn_stdin_failed".to_owned())?;
        liveness_writer
            .write_all(containment::hex_token(&token).as_bytes())
            .and_then(|()| liveness_writer.write_all(b"\n"))
            .and_then(|()| liveness_writer.flush())
            .map_err(|_| "native_resident_spawn_auth_failed".to_owned())?;
        let owner_start_marker = process_start_marker(owner_process_id).ok();
        let child_done = Arc::new(AtomicBool::new(false));
        let watcher_done = Arc::clone(&child_done);
        let watcher_base = state_base.to_owned();
        let watcher = thread::spawn(move || {
            let mut no_lease_since = None;
            loop {
                if watcher_done.load(Ordering::Acquire) {
                    break;
                }
                let owner_alive = owner_start_marker.as_deref().is_some_and(|expected| {
                    process_start_marker(owner_process_id).is_ok_and(|actual| actual == expected)
                });
                if owner_alive || lease::any_live_for_home(&watcher_base) {
                    no_lease_since = None;
                } else {
                    let started = no_lease_since.get_or_insert_with(Instant::now);
                    if started.elapsed() >= lease::LEASE_EXPIRY {
                        drop(liveness_writer);
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let status = child
            .wait()
            .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())?;
        child_done.store(true, Ordering::Release);
        let _ = watcher.join();
        if status.success() {
            Ok(())
        } else {
            Err("native_resident_managed_exit_failed".to_owned())
        }
    }
}

pub(crate) fn parse_generation(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation > 0)
        .ok_or_else(|| "native_resident_generation_invalid".to_owned())
}

pub(crate) fn parse_process_id(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|process_id| *process_id > 0)
        .ok_or_else(|| "native_resident_owner_process_invalid".to_owned())
}

pub(crate) fn client_timeout(payload: &[u8]) -> Duration {
    let budget = crate::strict_json_value(payload)
        .ok()
        .and_then(|value| {
            value
                .get("deadline_budget_ms")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(750)
        .clamp(1, 9_000);
    Duration::from_millis(budget)
}

#[cfg(test)]
use client_stream::{
    read_frame as read_client_stream_frame, write_frame as write_client_stream_frame,
};
#[cfg(test)]
#[path = "managed_resident_tests.rs"]
mod tests;
