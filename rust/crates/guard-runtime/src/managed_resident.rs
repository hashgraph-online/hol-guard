#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
#[cfg(not(windows))]
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[path = "managed_resident_transport.rs"]
mod managed_resident_transport;
#[cfg(windows)]
#[path = "managed_resident_windows.rs"]
mod managed_resident_windows;
#[path = "resident_state_retirement.rs"]
mod resident_state_retirement;
#[path = "resident_restart_budget.rs"]
mod restart_budget;

#[cfg(not(windows))]
use crate::resident_state::validate_package_process_identity;
use crate::resident_state::{
    acquire_startup_lock, clear_stale_startup_lock, discover_states, next_generation,
    runtime_digest, state_scope, token_from_state,
};

const CLIENT_START_TIMEOUT: Duration = Duration::from_millis(600);
const CLIENT_RETRY_DELAY: Duration = Duration::from_millis(5);
const MANAGED_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MANAGED_OWNER_LOCK_FILE_NAME: &str = "managed-resident-owner.v1.lock";
const MANAGED_STOP_TIMEOUT: Duration = Duration::from_secs(2);
static MANAGED_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Lifetime owner lock for the resident scope.
///
/// Unix keeps an open, verified directory descriptor and locks both the
/// directory and its named marker. This prevents an ordinary second process
/// from starting a second resident even if the marker pathname is replaced.
/// A same-UID actor that can deliberately mutate the private directory while
/// this process runs remains an OS-account trust limitation; callers must
/// still validate published state and process identity on every connection.
struct ManagedOwnerLock {
    _file: File,
    #[cfg(unix)]
    _directory: File,
}

fn acquire_managed_owner_lock(scope: &Path) -> Result<ManagedOwnerLock, String> {
    #[cfg(unix)]
    let directory = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let mut directory_options = OpenOptions::new();
        directory_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = directory_options
            .open(scope)
            .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
        let metadata = directory
            .metadata()
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        let path_metadata = std::fs::symlink_metadata(scope)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        if !metadata.is_dir()
            || path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || metadata.dev() != path_metadata.dev()
            || metadata.ino() != path_metadata.ino()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_owner_lock_not_private".to_owned());
        }
        fs2::FileExt::try_lock_exclusive(&directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                "native_resident_owner_busy".to_owned()
            } else {
                "native_resident_owner_lock_failed".to_owned()
            }
        })?;
        directory
    };
    let path = scope.join(MANAGED_OWNER_LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&path)
        .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
    if !metadata.is_file() {
        return Err("native_resident_owner_lock_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path_metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        let parent_uid = path
            .parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .map(|parent| parent.uid());
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
            || parent_uid != Some(metadata.uid())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_owner_lock_not_private".to_owned());
        }
    }
    #[cfg(windows)]
    crate::resident_state::verify_windows_private_path(&path, false)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "native_resident_owner_busy".to_owned()
        } else {
            "native_resident_owner_lock_failed".to_owned()
        }
    })?;
    Ok(ManagedOwnerLock {
        _file: file,
        #[cfg(unix)]
        _directory: directory,
    })
}

pub(crate) fn request_shutdown() {
    MANAGED_SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

fn shutdown_requested() -> bool {
    MANAGED_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

fn is_stale_process_identity_error(error: &str) -> bool {
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
            Err(error)
                if error == "native_client_connect_failed"
                    || is_stale_process_identity_error(&error) => {}
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
    #[cfg(windows)]
    return managed_resident_windows::spawn_managed(state_base, generation, digest, token);
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
    let deadline = Instant::now() + MANAGED_STOP_TIMEOUT;
    if try_states(&scope, &digest, request, deadline)?.is_some() {
        while Instant::now() < deadline {
            if discover_states(&scope, &digest)?.is_empty() {
                return Ok(());
            }
            thread::sleep(CLIENT_RETRY_DELAY);
        }
        return Err("native_resident_stop_timeout".to_owned());
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
    let scope = state_scope(state_base, expected_digest)?;
    let _owner_lock = acquire_managed_owner_lock(&scope)?;
    let policy_store = std::sync::Arc::new(
        crate::policy_store::PolicySnapshotStore::new_with_resident_generation(
            state_base,
            expected_digest,
            generation,
        )?,
    );
    let token = crate::read_resident_auth_token()?;
    let owner_alive = crate::resident_stdin_liveness();
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
    if generation == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let token = crate::read_resident_auth_token()?;
    #[cfg(windows)]
    return managed_resident_windows::supervise_managed(
        state_base,
        generation,
        expected_digest,
        &token,
    );
    #[cfg(not(windows))]
    {
        let executable = std::env::current_exe()
            .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
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
