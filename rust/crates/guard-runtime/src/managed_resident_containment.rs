#![forbid(unsafe_code)]

#[cfg(windows)]
use guard_runtime_windows_process::ManagedChild;
#[cfg(not(windows))]
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use std::time::Instant;

use crate::resident_state::{
    discover_states, process_start_marker, runtime_digest, token_from_state,
    validate_package_process_identity, validate_runtime_process_identity, ResidentState,
};

#[cfg(not(windows))]
pub(super) type SpawnedManaged = Child;
#[cfg(windows)]
pub(super) type SpawnedManaged = ManagedChild;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ManagedProcessIdentity {
    process_id: u32,
    start_marker: Option<String>,
    runtime_digest: Option<String>,
}

fn state_process_identity(state: &ResidentState) -> ManagedProcessIdentity {
    ManagedProcessIdentity {
        process_id: state.process_id,
        start_marker: Some(state.process_start_marker.clone()),
        runtime_digest: Some(state.runtime_sha256.clone()),
    }
}

pub(super) fn state_process_identities(states: &[ResidentState]) -> Vec<ManagedProcessIdentity> {
    states
        .iter()
        // The owner is a shared client lease, not a managed resident.  A
        // stop request must never wait for or terminate that requester.
        .map(state_process_identity)
        .collect()
}

pub(super) fn spawn_managed_for_owner(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
    owner_process_id: u32,
) -> Result<SpawnedManaged, String> {
    #[cfg(windows)]
    return super::managed_resident_windows::spawn_managed(
        state_base,
        generation,
        digest,
        token,
        owner_process_id,
    );
    #[cfg(not(windows))]
    {
        let executable = std::env::current_exe()
            .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
        let mut command = Command::new(executable);
        command
            .arg("supervise-managed")
            .arg("--state-dir")
            .arg(state_base)
            .arg("--generation")
            .arg(generation.to_string())
            .arg("--owner-process-id")
            .arg(owner_process_id.to_string())
            .arg("--runtime-sha256")
            .arg(digest)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The supervisor and serving child form one containment unit.  The
        // child inherits this group before it can run, closing the startup
        // timeout race that otherwise strands serve-managed at PID 1.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "native_resident_spawn_failed".to_owned())?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            let _ = terminate_spawned_managed(&mut child);
            "native_resident_spawn_stdin_failed".to_owned()
        })?;
        let write_result = stdin
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush());
        if write_result.is_err() {
            let _ = terminate_spawned_managed(&mut child);
            return Err("native_resident_spawn_auth_failed".to_owned());
        }
        Ok(child)
    }
}

pub(super) fn hex_token(token: &[u8]) -> String {
    let mut output = String::with_capacity(token.len() * 2);
    for byte in token {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn child_process_id(child: &SpawnedManaged) -> u32 {
    child.id()
}

#[cfg(not(windows))]
pub(super) fn terminate_spawned_managed(child: &mut SpawnedManaged) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?
        .is_some()
    {
        return Ok(());
    }
    let process_id = child.id();
    let start_marker = process_start_marker(process_id).ok();
    let runtime_identity_proven = start_marker.as_deref().is_some_and(|marker| {
        runtime_digest().is_ok_and(|digest| {
            validate_runtime_process_identity(process_id, marker, &digest).is_ok()
        })
    });
    if runtime_identity_proven {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        // spawn_managed_for_owner sets process_group(0), making the
        // supervisor PID the group ID inherited by serve-managed.  Keep the
        // identity proof immediately before addressing the group so a stale
        // or reused PID can never authorize a broad kill.
        match kill(Pid::from_raw(-(process_id as i32)), Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(_) => return Err("native_resident_spawn_containment_failed".to_owned()),
        }
    } else {
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("native_resident_spawn_containment_failed".to_owned()),
        }
    }
    child
        .wait()
        .map(|_| ())
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())
}

#[cfg(windows)]
pub(super) fn terminate_spawned_managed(child: &mut SpawnedManaged) -> Result<(), String> {
    child
        .terminate_with_timeout(super::MANAGED_STOP_TIMEOUT)
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())
}

fn process_is_alive(identity: &ManagedProcessIdentity) -> Result<bool, String> {
    let Some(start_marker) = identity.start_marker.as_deref() else {
        return Ok(false);
    };
    let identity_valid = match identity.runtime_digest.as_deref() {
        Some(digest) => {
            validate_runtime_process_identity(identity.process_id, start_marker, digest).is_ok()
        }
        None => validate_package_process_identity(identity.process_id, start_marker).is_ok(),
    };
    if !identity_valid {
        return Ok(false);
    }
    if identity.process_id == std::process::id() {
        return Ok(true);
    }
    #[cfg(windows)]
    let platform_result =
        guard_runtime_windows_process::wait_for_process_exit(identity.process_id, Duration::ZERO)
            .map(|exited| !exited)
            .map_err(|_| "native_resident_process_liveness_failed".to_owned());
    #[cfg(not(windows))]
    let platform_result: Result<bool, String> = Ok(true);
    platform_result
}

fn terminate_managed_process(
    identity: &ManagedProcessIdentity,
    timeout: Duration,
) -> Result<(), String> {
    #[cfg(not(windows))]
    let _ = timeout;
    let Some(start_marker) = identity.start_marker.as_deref() else {
        return Ok(());
    };
    if !process_is_alive(identity)? {
        return Ok(());
    }
    #[cfg(windows)]
    let platform_result = guard_runtime_windows_process::terminate_process_verified(
        identity.process_id,
        Some(start_marker),
        timeout,
    )
    .and_then(|confirmed| {
        confirmed
            .then_some(())
            .ok_or_else(|| std::io::Error::other("native_resident_spawn_containment_failed"))
    })
    .map_err(|_| "native_resident_spawn_containment_failed".to_owned());
    #[cfg(unix)]
    let platform_result = {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        let identity_valid = match identity.runtime_digest.as_deref() {
            Some(digest) => {
                validate_runtime_process_identity(identity.process_id, start_marker, digest).is_ok()
            }
            None => validate_package_process_identity(identity.process_id, start_marker).is_ok(),
        };
        if !identity_valid {
            return Ok(());
        }
        match kill(Pid::from_raw(identity.process_id as i32), Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(_) => Err("native_resident_spawn_containment_failed".to_owned()),
        }
    };
    platform_result
}

fn generation_process_ids(
    states: &[ResidentState],
    known_processes: &[ManagedProcessIdentity],
) -> Vec<ManagedProcessIdentity> {
    let mut process_ids = known_processes.to_vec();
    process_ids.extend(state_process_identities(states));
    process_ids.retain(|identity| identity.process_id != std::process::id());
    process_ids.sort_unstable_by(|left, right| {
        left.process_id
            .cmp(&right.process_id)
            .then(left.start_marker.cmp(&right.start_marker))
    });
    process_ids.dedup();
    process_ids
}

fn any_process_alive(process_ids: &[ManagedProcessIdentity]) -> Result<bool, String> {
    for process_id in process_ids {
        if process_is_alive(process_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn wait_for_generation_containment(
    scope: &Path,
    digest: &str,
    generation: u64,
    token: &[u8],
    known_processes: &[ManagedProcessIdentity],
) -> Result<(), String> {
    let deadline = Instant::now() + super::MANAGED_STOP_TIMEOUT;
    loop {
        let states = discover_states(scope, digest)?;
        let generation_states = states
            .iter()
            .filter(|state| state.generation == generation)
            .cloned()
            .collect::<Vec<_>>();
        let process_ids = generation_process_ids(&generation_states, known_processes);
        let timeout = deadline.saturating_duration_since(Instant::now());
        for process_id in &process_ids {
            terminate_managed_process(process_id, timeout)?;
        }
        for state in &generation_states {
            let identity = state_process_identity(state);
            if !process_is_alive(&identity)? {
                super::resident_state_retirement::retire_state(
                    scope,
                    state.generation,
                    state.process_id,
                    &state.process_start_marker,
                    digest,
                    token,
                );
            }
        }
        let state_remains = discover_states(scope, digest)?
            .iter()
            .any(|state| state.generation == generation);
        let processes_remain = any_process_alive(&process_ids)?;
        if !state_remains && !processes_remain {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("native_resident_spawn_containment_failed".to_owned());
        }
        std::thread::sleep(super::CLIENT_RETRY_DELAY);
    }
}

pub(super) fn wait_for_stop_containment(
    scope: &Path,
    digest: &str,
    deadline: Instant,
    known_processes: &[ManagedProcessIdentity],
) -> Result<(), String> {
    loop {
        let states = discover_states(scope, digest)?;
        let process_ids = generation_process_ids(&states, known_processes);
        let processes_remain = any_process_alive(&process_ids)?;
        if states.is_empty() && !processes_remain {
            return Ok(());
        }
        if Instant::now() >= deadline {
            for process_id in &process_ids {
                terminate_managed_process(process_id, Duration::ZERO)?;
            }
            for state in &states {
                let identity = state_process_identity(state);
                if !process_is_alive(&identity)? {
                    if let Ok(token) = token_from_state(state) {
                        super::resident_state_retirement::retire_state(
                            scope,
                            state.generation,
                            state.process_id,
                            &state.process_start_marker,
                            digest,
                            &token,
                        );
                    }
                }
            }
            let states_remaining = !discover_states(scope, digest)?.is_empty();
            let processes_remaining = any_process_alive(&process_ids)?;
            if !states_remaining && !processes_remaining {
                return Ok(());
            }
            return Err("native_resident_stop_timeout".to_owned());
        }
        std::thread::sleep(super::CLIENT_RETRY_DELAY);
    }
}

pub(super) fn contain_spawned_managed(
    child: &mut SpawnedManaged,
    scope: &Path,
    digest: &str,
    generation: u64,
    token: &[u8],
) -> Result<(), String> {
    let process_id = child_process_id(child);
    let known_processes = [ManagedProcessIdentity {
        process_id,
        start_marker: process_start_marker(process_id).ok(),
        runtime_digest: runtime_digest().ok(),
    }];
    terminate_spawned_managed(child)?;
    wait_for_generation_containment(scope, digest, generation, token, &known_processes)
}

pub(super) fn is_stale_process_identity_error(error: &str) -> bool {
    matches!(
        error,
        "native_resident_process_identity_unavailable"
            | "native_resident_process_identity_mismatch"
    )
}

pub(super) fn is_retryable_live_request_error(
    error: &crate::resident_client::ResidentClientError,
) -> bool {
    error.code == "native_client_connect_failed"
        || is_stale_process_identity_error(&error.code)
        || (error.code == "native_client_auth_nonce_failed" && error.retryable_teardown)
}

pub(super) fn state_owner_is_live(state: &ResidentState) -> bool {
    process_start_marker(state.owner_process_id)
        .is_ok_and(|actual| actual == state.owner_process_start_marker)
}

pub(super) fn skip_failed_home_state_request(
    error: &crate::resident_client::ResidentClientError,
    same_runtime: bool,
    state: &ResidentState,
) -> bool {
    is_retryable_live_request_error(error)
        || !state_owner_is_live(state)
        || (same_runtime
            && validate_package_process_identity(state.process_id, &state.process_start_marker)
                .is_err())
        || (!same_runtime
            && validate_runtime_process_identity(
                state.process_id,
                &state.process_start_marker,
                &state.runtime_sha256,
            )
            .is_err())
}
