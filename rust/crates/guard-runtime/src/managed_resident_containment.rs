#![forbid(unsafe_code)]

#[cfg(windows)]
use guard_runtime_windows_process::ManagedChild;
#[cfg(not(windows))]
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::time::Duration;
use std::time::Instant;

use crate::resident_state::{
    discover_states, token_from_state, validate_package_process_identity, ResidentState,
};

#[cfg(not(windows))]
pub(super) type SpawnedManaged = Child;
#[cfg(windows)]
pub(super) type SpawnedManaged = ManagedChild;

pub(super) fn spawn_managed(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
) -> Result<SpawnedManaged, String> {
    #[cfg(windows)]
    return super::managed_resident_windows::spawn_managed(state_base, generation, digest, token);
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
            .arg("--runtime-sha256")
            .arg(digest)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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
    let status = child
        .try_wait()
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
    if status.is_some() {
        return Ok(());
    }
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("native_resident_spawn_containment_failed".to_owned()),
    }
    child
        .wait()
        .map(|_| ())
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())
}

#[cfg(windows)]
pub(super) fn terminate_spawned_managed(child: &mut SpawnedManaged) -> Result<(), String> {
    child
        .terminate()
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())
}

fn process_is_alive(process_id: u32) -> Result<bool, String> {
    if process_id == std::process::id() {
        return Ok(true);
    }
    if validate_package_process_identity(process_id).is_err() {
        return Ok(false);
    }
    #[cfg(windows)]
    {
        return guard_runtime_windows_process::wait_for_process_exit(process_id, Duration::ZERO)
            .map(|exited| !exited)
            .map_err(|_| "native_resident_process_liveness_failed".to_owned());
    }
    #[cfg(not(windows))]
    {
        Ok(true)
    }
}

fn terminate_managed_process(process_id: u32) -> Result<(), String> {
    if !process_is_alive(process_id)? {
        return Ok(());
    }
    #[cfg(windows)]
    {
        guard_runtime_windows_process::terminate_process(process_id)
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        match kill(Pid::from_raw(process_id as i32), Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(_) => Err("native_resident_spawn_containment_failed".to_owned()),
        }
    }
}

fn generation_process_ids(states: &[ResidentState], known_process_ids: &[u32]) -> Vec<u32> {
    let mut process_ids = known_process_ids.to_vec();
    for state in states {
        process_ids.push(state.process_id);
        process_ids.push(state.owner_process_id);
    }
    process_ids.retain(|process_id| *process_id != std::process::id());
    process_ids.sort_unstable();
    process_ids.dedup();
    process_ids
}

fn any_process_alive(process_ids: &[u32]) -> Result<bool, String> {
    for process_id in process_ids {
        if process_is_alive(*process_id)? {
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
    known_process_ids: &[u32],
) -> Result<(), String> {
    let deadline = Instant::now() + super::MANAGED_STOP_TIMEOUT;
    loop {
        let states = discover_states(scope, digest)?;
        let generation_states = states
            .iter()
            .filter(|state| state.generation == generation)
            .cloned()
            .collect::<Vec<_>>();
        let process_ids = generation_process_ids(&generation_states, known_process_ids);
        for process_id in &process_ids {
            terminate_managed_process(*process_id)?;
        }
        for state in &generation_states {
            if !process_is_alive(state.process_id)? {
                super::resident_state_retirement::retire_state(
                    scope,
                    state.generation,
                    state.process_id,
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
    known_process_ids: &[u32],
) -> Result<(), String> {
    loop {
        let states = discover_states(scope, digest)?;
        let process_ids = generation_process_ids(&states, known_process_ids);
        let processes_remain = any_process_alive(&process_ids)?;
        if states.is_empty() && !processes_remain {
            return Ok(());
        }
        if Instant::now() >= deadline {
            for process_id in &process_ids {
                terminate_managed_process(*process_id)?;
            }
            for state in &states {
                if !process_is_alive(state.process_id)? {
                    if let Ok(token) = token_from_state(state) {
                        super::resident_state_retirement::retire_state(
                            scope,
                            state.generation,
                            state.process_id,
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
    let known_process_ids = [child_process_id(child)];
    terminate_spawned_managed(child)?;
    wait_for_generation_containment(scope, digest, generation, token, &known_process_ids)
}
