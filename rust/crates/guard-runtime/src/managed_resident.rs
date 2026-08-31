#![forbid(unsafe_code)]

#[cfg(unix)]
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[path = "resident_restart_budget.rs"]
mod restart_budget;

#[cfg(unix)]
use crate::resident_state::socket_directory;
#[cfg(not(windows))]
use crate::resident_state::validate_package_process_identity;
use crate::resident_state::{
    acquire_startup_lock, clear_stale_startup_lock, discover_states, next_generation,
    publish_state, runtime_digest, state_scope, token_from_state,
};

const CLIENT_START_TIMEOUT: Duration = Duration::from_millis(600);
const CLIENT_RETRY_DELAY: Duration = Duration::from_millis(5);
const MANAGED_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
#[cfg(windows)]
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
static MANAGED_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn request_shutdown() {
    MANAGED_SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

fn shutdown_requested() -> bool {
    MANAGED_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

fn try_states(
    scope: &Path,
    digest: &str,
    payload: &[u8],
    deadline: Instant,
) -> Result<Option<Vec<u8>>, String> {
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
            Ok(response) => return Ok(Some(response)),
            Err(error) if error == "native_client_connect_failed" => {}
            Err(_) => return Err("native_resident_live_request_failed".to_owned()),
        }
    }
    Ok(None)
}

fn spawn_managed(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
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
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
    }
    let mut child = command
        .spawn()
        .map_err(|_| "native_resident_spawn_failed".to_owned())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "native_resident_spawn_stdin_failed".to_owned())?;
    stdin
        .write_all(hex_token(token).as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.flush())
        .map_err(|_| "native_resident_spawn_auth_failed".to_owned())?;
    Ok(())
}

fn hex_token(token: &[u8]) -> String {
    let mut output = String::with_capacity(token.len() * 2);
    for byte in token {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn client_request(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    if timeout.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let overall_deadline = Instant::now() + timeout;
    let digest = runtime_digest()?;
    let scope = state_scope(state_base, &digest)?;
    if let Some(response) = try_states(&scope, &digest, payload, overall_deadline)? {
        return Ok(response);
    }
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let mut lock = acquire_startup_lock(&scope)?;
    if lock.is_none() && clear_stale_startup_lock(&scope, &digest)? {
        lock = acquire_startup_lock(&scope)?;
    }
    if lock.is_none() {
        let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
        while Instant::now() < deadline {
            if let Some(response) = try_states(&scope, &digest, payload, overall_deadline)? {
                return Ok(response);
            }
            thread::sleep(CLIENT_RETRY_DELAY);
        }
        if clear_stale_startup_lock(&scope, &digest)? {
            lock = acquire_startup_lock(&scope)?;
        }
    }
    let _startup_lock = lock.ok_or_else(|| "native_resident_start_in_progress".to_owned())?;
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    if let Some(response) = try_states(&scope, &digest, payload, overall_deadline)? {
        return Ok(response);
    }
    restart_budget::consume(&scope)?;
    let generation = next_generation(&scope, &digest)?;
    let mut token = [0u8; crate::AUTH_TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|_| "native_client_random_failed".to_owned())?;
    spawn_managed(state_base, generation, &digest, &token)?;
    let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
    while Instant::now() < deadline {
        if let Some(response) = try_states(&scope, &digest, payload, overall_deadline)? {
            return Ok(response);
        }
        thread::sleep(CLIENT_RETRY_DELAY);
    }
    Err("native_resident_start_timeout".to_owned())
}

pub(crate) fn stop_managed(state_base: &Path) -> Result<(), String> {
    let digest = runtime_digest()?;
    let scope = state_scope(state_base, &digest)?;
    let request = br#"{"operation":"shutdown","request":{}}"#;
    if try_states(
        &scope,
        &digest,
        request,
        Instant::now() + Duration::from_millis(250),
    )?
    .is_some()
    {
        return Ok(());
    }
    Err("native_resident_stop_unavailable".to_owned())
}

#[cfg(unix)]
fn serve_unix_managed(
    scope: &Path,
    generation: u64,
    owner_process_id: u32,
    digest: &str,
    token: [u8; crate::AUTH_TOKEN_BYTES],
    owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    let socket_parent = socket_directory(scope, digest)?;
    let path = socket_parent.join(format!("h3-{}-{generation:016x}.sock", &digest[..8]));
    if path.as_os_str().as_encoded_bytes().len() > 100 {
        return Err("native_socket_path_too_long".to_owned());
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(metadata) if metadata.file_type().is_socket() => {
            return Err("native_socket_generation_collision".to_owned())
        }
        Ok(_) => return Err("native_socket_existing_path_rejected".to_owned()),
        Err(_) => return Err("native_socket_stat_failed".to_owned()),
    }
    let listener = UnixListener::bind(&path).map_err(|_| "native_socket_bind_failed".to_owned())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "native_socket_permissions_failed".to_owned())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "native_socket_nonblocking_failed".to_owned())?;
    publish_state(
        scope,
        generation,
        owner_process_id,
        digest,
        "unix",
        path.to_string_lossy().into_owned(),
        &token,
    )?;
    let result = managed_accept_loop(listener, Arc::new(token), owner_alive);
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        let _ = fs::remove_file(path);
    }
    result
}

#[cfg(unix)]
fn managed_accept_loop(
    listener: std::os::unix::net::UnixListener,
    token: Arc<[u8; crate::AUTH_TOKEN_BYTES]>,
    owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    let sender = crate::start_resident_workers(token);
    let mut last_activity = Instant::now();
    let mut failures = 0;
    while owner_alive.load(Ordering::Acquire)
        && last_activity.elapsed() < MANAGED_IDLE_TIMEOUT
        && !shutdown_requested()
    {
        match listener.accept() {
            Ok((stream, _)) => {
                failures = 0;
                last_activity = Instant::now();
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                crate::admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if crate::hardening::classify_io_error(&error)
                    != crate::hardening::IoFailureClass::Other =>
            {
                failures += 1;
                thread::sleep(crate::hardening::accept_retry_delay(failures, &error));
            }
            Err(_) => return Err("native_socket_accept_failed".to_owned()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn serve_unix_managed(
    _scope: &Path,
    _generation: u64,
    _owner_process_id: u32,
    _digest: &str,
    _token: [u8; crate::AUTH_TOKEN_BYTES],
    _owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    Err("native_unix_socket_not_available".to_owned())
}

fn serve_loopback_managed(
    scope: &Path,
    generation: u64,
    owner_process_id: u32,
    digest: &str,
    token: [u8; crate::AUTH_TOKEN_BYTES],
    owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "native_resident_loopback_bind_failed".to_owned())?;
    let address = listener
        .local_addr()
        .map_err(|_| "native_resident_loopback_addr_failed".to_owned())?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("native_resident_loopback_addr_invalid".to_owned());
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| "native_resident_loopback_nonblocking_failed".to_owned())?;
    publish_state(
        scope,
        generation,
        owner_process_id,
        digest,
        "loopback",
        address.to_string(),
        &token,
    )?;
    let sender = crate::start_resident_workers(Arc::new(token));
    let mut last_activity = Instant::now();
    let mut failures = 0;
    while owner_alive.load(Ordering::Acquire)
        && last_activity.elapsed() < MANAGED_IDLE_TIMEOUT
        && !shutdown_requested()
    {
        match listener.accept() {
            Ok((stream, peer)) => {
                if peer.ip() != Ipv4Addr::LOCALHOST {
                    continue;
                }
                failures = 0;
                last_activity = Instant::now();
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                crate::admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if crate::hardening::classify_io_error(&error)
                    != crate::hardening::IoFailureClass::Other =>
            {
                failures += 1;
                thread::sleep(crate::hardening::accept_retry_delay(failures, &error));
            }
            Err(_) => return Err("native_resident_loopback_accept_failed".to_owned()),
        }
    }
    Ok(())
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
    let scope = state_scope(state_base, expected_digest)?;
    let token = crate::read_resident_auth_token()?;
    let owner_alive = crate::resident_stdin_liveness();
    if cfg!(unix) {
        serve_unix_managed(
            &scope,
            generation,
            owner_process_id,
            expected_digest,
            token,
            owner_alive,
        )
    } else {
        serve_loopback_managed(
            &scope,
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
    if generation == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let token = crate::read_resident_auth_token()?;
    let executable =
        std::env::current_exe().map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let mut child = Command::new(executable)
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
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "native_resident_spawn_failed".to_owned())?;
    let mut liveness_writer = child
        .stdin
        .take()
        .ok_or_else(|| "native_resident_spawn_stdin_failed".to_owned())?;
    liveness_writer
        .write_all(hex_token(&token).as_bytes())
        .and_then(|()| liveness_writer.write_all(b"\n"))
        .and_then(|()| liveness_writer.flush())
        .map_err(|_| "native_resident_spawn_auth_failed".to_owned())?;
    let status = child
        .wait()
        .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())?;
    drop(liveness_writer);
    if status.success() {
        Ok(())
    } else {
        Err("native_resident_managed_exit_failed".to_owned())
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
#[path = "managed_resident_tests.rs"]
mod tests;
