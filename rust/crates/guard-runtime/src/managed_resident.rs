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
#[path = "managed_resident_handoff.rs"]
mod handoff;
#[path = "managed_resident_lease.rs"]
mod lease;
pub(crate) use lease::client_request;
use lease::client_request_with_lease;
#[path = "managed_resident_client_request.rs"]
mod client_request_flow;
#[path = "managed_resident_transport.rs"]
mod managed_resident_transport;
#[cfg(windows)]
#[path = "managed_resident_windows.rs"]
mod managed_resident_windows;
#[path = "managed_resident_owner_lock.rs"]
mod owner_lock;
pub(crate) use owner_lock::ManagedOwnerLock;
#[path = "resident_state_retirement.rs"]
mod resident_state_retirement;
#[path = "resident_restart_budget.rs"]
mod restart_budget;

#[cfg(all(test, unix))]
const MANAGED_OWNER_LOCK_FILE_NAME: &str = owner_lock::MANAGED_OWNER_LOCK_FILE_NAME;

use crate::resident_state::{
    discover_home_states_prefer, process_start_marker, runtime_digest, state_scope,
    token_from_state,
};

pub(crate) fn client_stream(state_base: &Path) -> Result<(), String> {
    client_stream::run(state_base)
}

const MANAGED_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MANAGED_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_RETRY_DELAY: Duration = Duration::from_millis(5);
static MANAGED_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn client_request_with_deadline(
    state_base: &Path,
    payload: &[u8],
    overall_deadline: Instant,
    client_lease: &lease::ClientLease,
) -> Result<Vec<u8>, String> {
    client_request_flow::client_request_with_deadline(
        state_base,
        payload,
        overall_deadline,
        client_lease,
    )
}

pub(crate) fn acquire_managed_owner_lock(
    scope: &Path,
) -> Result<owner_lock::ManagedOwnerLock, String> {
    owner_lock::acquire(scope)
}

pub(crate) fn request_shutdown() {
    MANAGED_SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

pub(crate) fn shutdown_response_sent() {}

fn shutdown_requested() -> bool {
    MANAGED_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

fn managed_owner_liveness(
    state_base: &Path,
    owner_process_id: u32,
    owner_start_marker: String,
    runtime_digest: &str,
) -> Arc<AtomicBool> {
    let alive = Arc::new(AtomicBool::new(true));
    let watcher_alive = Arc::clone(&alive);
    let base = state_base.to_owned();
    let digest = runtime_digest.to_owned();
    thread::spawn(move || {
        let mut no_lease_since = None;
        loop {
            if shutdown_requested() {
                watcher_alive.store(false, Ordering::Release);
                break;
            }
            let owner_alive = process_start_marker(owner_process_id)
                .is_ok_and(|actual| actual == owner_start_marker);
            // Only clients of this runtime keep an ownerless resident alive.
            // A newer runtime's clients must not pin an older resident that
            // holds the home-wide owner lock and blocks their own resident.
            if owner_alive || lease::any_live(&base, &digest) {
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
    runtime_digest: &str,
) -> Arc<AtomicBool> {
    let owner_alive = managed_owner_liveness(
        state_base,
        owner_process_id,
        owner_start_marker,
        runtime_digest,
    );
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

pub(crate) fn stop_managed(state_base: &Path, retire_clients: bool) -> Result<(), String> {
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
        if retire_clients {
            lease::retire_clients_for_update(state_base, &digest, deadline)?;
        }
        return Err("native_resident_stop_unavailable".to_owned());
    };
    if retire_clients {
        lease::retire_clients_for_update(state_base, &digest, deadline)?;
    }
    let process_ids = containment::state_process_identities(std::slice::from_ref(&state));
    let token = token_from_state(&state)?;
    let identity = crate::resident_client::ExpectedProcessIdentity {
        process_id: state.process_id,
        start_marker: &state.process_start_marker,
        runtime: crate::resident_client::ExpectedRuntime::Digest(&state.runtime_sha256),
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
        containment::wait_for_stop_containment(&scope, &digest, deadline, &process_ids)?;
        let _ = restart_budget::clear(&scope);
        return Ok(());
    }
    // Clean up after a resident that died without a shutdown request, so
    // the next stop reports an empty scope instead of a stale generation.
    containment::retire_exited_states(&scope, &digest)?;
    Err("native_resident_stop_unavailable".to_owned())
}

/// Forget the crash-loop history of this runtime's resident so the next
/// request may start it immediately.  This only lifts the restart pacing; the
/// resident itself is still started by the normal authenticated client path.
pub(crate) fn reset_restart_budget(state_base: &Path) -> Result<(), String> {
    let digest = runtime_digest()?;
    let scope = state_scope(state_base, &digest)?;
    restart_budget::clear(&scope)
}

pub(crate) fn serve_managed(
    state_base: &Path,
    generation: u64,
    owner_process_id: u32,
    expected_digest: &str,
) -> Result<(), String> {
    MANAGED_SHUTDOWN_REQUESTED.store(false, Ordering::Release);
    let startup_started = crate::resident_diagnostics::enabled().then(Instant::now);
    // Decode the packaged command program while the executable self-check
    // runs. Policy admission waits on the same OnceLock, so nothing uses the
    // program before the identity check below has passed.
    thread::spawn(|| {
        let _ = guard_command::native_command_program::packaged_command_program();
    });
    if generation == 0 || owner_process_id == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let owner_start_marker = process_start_marker(owner_process_id)?;
    let scope = state_scope(state_base, expected_digest)?;
    let owner_lock = acquire_managed_owner_lock(state_base)?;
    // Build the immutable catalog read snapshot off the request path so the
    // first catalog_read does not pay for it; failures surface on that read.
    thread::spawn(|| {
        let _ = guard_command::catalog_read_model::packaged_catalog_read_snapshot();
    });
    // Initialize before fallible policy startup so every client can see a
    // resident still starting. This guard drops before owner_lock on all exits.
    let _diagnostic_lifetime =
        crate::resident_diagnostics::install_managed_sink(state_base, &owner_lock);
    crate::resident_diagnostics::start(crate::resident_diagnostics::Phase::ResidentStartup);
    let startup = (|| -> Result<_, String> {
        let policy_store = std::sync::Arc::new(
            crate::policy_store::PolicySnapshotStore::new_with_resident_generation(
                state_base,
                expected_digest,
                generation,
            )?,
        );
        let token = crate::read_resident_auth_token()?;
        let owner_alive = combine_liveness(
            state_base,
            owner_process_id,
            owner_start_marker,
            expected_digest,
        );
        Ok((policy_store, token, owner_alive))
    })();
    if let Some(started) = startup_started {
        crate::resident_diagnostics::finish_since(
            crate::resident_diagnostics::Phase::ResidentStartup,
            if startup.is_ok() {
                crate::resident_diagnostics::Status::Ok
            } else {
                crate::resident_diagnostics::Status::Error
            },
            started,
        );
    }
    let (policy_store, token, owner_alive) = startup?;
    if cfg!(unix) {
        managed_resident_transport::serve_unix_managed(
            (&scope, &owner_lock),
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
        let mut child = Command::new(&executable);
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
        // Keep the serving child in the supervisor's group for joint containment.
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
        let child_done = Arc::new(AtomicBool::new(false));
        let watcher = spawn_owner_lease_watcher(
            executable,
            state_base,
            expected_digest,
            owner_process_id,
            liveness_writer,
            Arc::clone(&child_done),
        );
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

/// Hold the serving child's stdin until its owner has exited and no client of
/// this runtime has held a lease for `LEASE_EXPIRY`, then close it so the child
/// sees EOF and shuts down. Without this an ownerless resident lingers until
/// its idle timeout.
fn spawn_owner_lease_watcher<W: Send + 'static>(
    executable: std::path::PathBuf,
    state_base: &Path,
    expected_digest: &str,
    owner_process_id: u32,
    liveness_writer: W,
    child_done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    let owner_start_marker = process_start_marker(owner_process_id).ok();
    let watcher_base = state_base.to_owned();
    let watcher_digest = expected_digest.to_owned();
    thread::spawn(move || {
        let mut no_lease_since = None;
        loop {
            if child_done.load(Ordering::Acquire) {
                break;
            }
            if crate::resident_process_identity::executable_missing(&executable) {
                break;
            }
            let owner_alive = owner_start_marker.as_deref().is_some_and(|expected| {
                crate::resident_process_identity::running_process_start_marker(owner_process_id)
                    .is_ok_and(|actual| actual == expected)
            });
            if owner_alive || lease::any_live(&watcher_base, &watcher_digest) {
                no_lease_since = None;
            } else {
                let started = no_lease_since.get_or_insert_with(Instant::now);
                if started.elapsed() >= lease::LEASE_EXPIRY {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        drop(liveness_writer);
    })
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

/// Upper bound on a caller-supplied deadline. Every operation is capped at nine
/// seconds except the skill-directory scan, whose bounded tree walk may
/// legitimately read hundreds of megabytes and is granted a longer ceiling.
const CLIENT_TIMEOUT_CEILING_MS: u64 = 9_000;
/// Cold daemon-lifecycle startup. Python grants `_TIMEOUT_SECONDS` (10s) plus
/// `_COLD_START_ALLOWANCE_SECONDS` (20s) in `native_daemon_lifecycle.py`.
/// A packaged Windows resident can spend most of that creating the process
/// and scanning the binary before it answers; clamping the request to nine
/// seconds reports `native_resident_start_timeout` while the resident is
/// still starting.
const DAEMON_LIFECYCLE_TIMEOUT_CEILING_MS: u64 = 30_000;
const SKILL_SCAN_TIMEOUT_CEILING_MS: u64 = 60_000;
/// Contained local runners honour the caller's process timeout (up to ten
/// minutes) plus a minute of transport slack for the probe and snapshot, so their budget must not be clamped to the
/// nine-second ceiling that would abort a legitimate test run mid-flight. The
/// package-shim admin op shares it: a probe runs each installed shim under its
/// own per-shim timeout.
const CONTAINED_RUNNER_TIMEOUT_CEILING_MS: u64 = 670_000;
/// A Codex resume retry waits up to a minute for the app server to accept
/// the turn and up to its busy timeout for the store; the caller adds five
/// seconds of transport grace.
const CODEX_REQUEST_RESUME_TIMEOUT_CEILING_MS: u64 =
    guard_contracts::CODEX_REQUEST_RESUME_MAX_TIMEOUT_MS
        + guard_contracts::CODEX_REQUEST_RESUME_MAX_BUSY_TIMEOUT_MS
        + 5_000;

pub(crate) fn client_timeout(payload: &[u8]) -> Duration {
    let value = crate::strict_json_value(payload).ok();
    let ceiling = match value
        .as_ref()
        .and_then(|value| value.get("operation")?.as_str())
    {
        Some("skill_directory_identity" | "package_context_build") => SKILL_SCAN_TIMEOUT_CEILING_MS,
        Some(
            "contained_node_execute"
            | "contained_typescript_execute"
            | "contained_package_script_execute"
            | "shim_admin",
        ) => CONTAINED_RUNNER_TIMEOUT_CEILING_MS,
        Some("codex_request_resume") => CODEX_REQUEST_RESUME_TIMEOUT_CEILING_MS,
        Some("daemon_lifecycle_decide") => DAEMON_LIFECYCLE_TIMEOUT_CEILING_MS,
        _ => CLIENT_TIMEOUT_CEILING_MS,
    };
    let budget = value
        .as_ref()
        .and_then(|value| value.get("deadline_budget_ms")?.as_u64())
        .unwrap_or(750)
        .clamp(1, ceiling);
    Duration::from_millis(budget)
}

#[cfg(test)]
use client_stream::{
    read_frame as read_client_stream_frame, write_frame as write_client_stream_frame,
};
#[cfg(test)]
#[path = "managed_resident_tests.rs"]
mod tests;
