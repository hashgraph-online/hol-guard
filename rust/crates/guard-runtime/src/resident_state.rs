#![forbid(unsafe_code)]

use crate::resident_state_encoding::{decode_hex, hex_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[cfg(windows)]
#[path = "resident_state_windows.rs"]
mod windows_security;

const STATE_SCHEMA: &str = "hol-guard-resident-state.v3";
const STATE_FILE_PREFIX: &str = "generation-";
const STATE_FILE_SUFFIX: &str = ".json";
const STATE_MAC_LABEL: &[u8] = b"hol-guard-resident-state-v3\0";
const MAX_STATE_BYTES: u64 = 16 * 1024;
const MAX_STATE_FILES: usize = 64;
const RETAINED_STATE_FILES: usize = 8;
const MAX_RUNTIME_BYTES: u64 = 128 * 1024 * 1024;
const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentState {
    pub(crate) schema: String,
    pub(crate) generation: u64,
    pub(crate) process_id: u32,
    pub(crate) owner_process_id: u32,
    pub(crate) runtime_sha256: String,
    pub(crate) transport: String,
    pub(crate) endpoint: String,
    pub(crate) token_hex: String,
    pub(crate) created_ms: u64,
    pub(crate) state_mac: String,
}

pub(crate) struct StartupLock {
    path: PathBuf,
    nonce: String,
}

impl Drop for StartupLock {
    fn drop(&mut self) {
        let Ok(contents) = fs::read_to_string(&self.path) else {
            return;
        };
        if contents == self.nonce {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn now_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "native_resident_clock_invalid".to_owned())
}

fn private_file(path: &Path, create_new: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).create_new(create_new);
    if !create_new {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| "native_resident_state_write_failed".to_owned())?;
    #[cfg(windows)]
    windows_security::protect_windows_path(path, false)?;
    Ok(file)
}

fn ensure_private_directory(path: &Path, protect_windows: bool) -> Result<PathBuf, String> {
    #[cfg(not(windows))]
    let _ = protect_windows;
    let created = !path.exists();
    if created {
        fs::create_dir(path).map_err(|_| "native_resident_state_dir_create_failed".to_owned())?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "native_resident_state_dir_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("native_resident_state_dir_invalid".to_owned());
    }
    #[cfg(windows)]
    if protect_windows {
        if created {
            windows_security::protect_windows_path(path, true)?;
        } else {
            use windows_permissions::utilities::current_process_sid;
            let owner = current_process_sid()
                .map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
            windows_security::verify_windows_path(path, owner.as_ref())?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| "native_resident_state_dir_permissions_failed".to_owned())?;
        }
        let updated = fs::symlink_metadata(path)
            .map_err(|_| "native_resident_state_dir_stat_failed".to_owned())?;
        if updated.permissions().mode() & 0o077 != 0 {
            return Err("native_resident_state_dir_not_private".to_owned());
        }
    }
    let resolved = path
        .canonicalize()
        .map_err(|_| "native_resident_state_dir_resolve_failed".to_owned())?;
    #[cfg(windows)]
    {
        let profile = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .ok_or_else(|| "native_resident_user_profile_missing".to_owned())?
            .canonicalize()
            .map_err(|_| "native_resident_user_profile_invalid".to_owned())?;
        if !resolved.starts_with(profile) {
            return Err("native_resident_state_dir_outside_user_profile".to_owned());
        }
    }
    Ok(resolved)
}

fn executable_digest(executable: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(executable)
        .map_err(|_| "native_resident_runtime_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_RUNTIME_BYTES
    {
        return Err("native_resident_runtime_invalid".to_owned());
    }
    let mut file =
        File::open(executable).map_err(|_| "native_resident_runtime_read_failed".to_owned())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "native_resident_runtime_read_failed".to_owned())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_bytes(&hasher.finalize()))
}

pub(crate) fn runtime_digest() -> Result<String, String> {
    let executable =
        std::env::current_exe().map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    executable_digest(&executable)
}

pub(crate) fn validate_package_process_identity(process_id: u32) -> Result<(), String> {
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let executable = system
        .process(pid)
        .and_then(|process| process.exe())
        .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())?;
    let expected_path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let process_path = fs::canonicalize(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    if process_path != expected_path {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn state_scope(base: &Path, digest: &str) -> Result<PathBuf, String> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native_resident_runtime_digest_invalid".to_owned());
    }
    let base = ensure_private_directory(base, false)?;
    ensure_private_directory(&base.join(format!("resident-v3-{}", &digest[..16])), true)
}

#[cfg(unix)]
fn socket_directory_path(scope: &Path, digest: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(scope.as_os_str().as_encoded_bytes());
    let scope_digest = hex_bytes(&hasher.finalize());
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let temporary_root = Path::new("/private/tmp");
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let temporary_root = Path::new("/tmp");
    temporary_root.join(format!("hgr-{}-{}", &digest[..8], &scope_digest[..8]))
}

#[cfg(unix)]
pub(crate) fn socket_directory(scope: &Path, digest: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;

    let directory = ensure_private_directory(&socket_directory_path(scope, digest), true)?;
    let scope_owner = fs::symlink_metadata(scope)
        .map_err(|_| "native_resident_state_dir_stat_failed".to_owned())?
        .uid();
    let socket_owner = fs::symlink_metadata(&directory)
        .map_err(|_| "native_resident_socket_dir_stat_failed".to_owned())?
        .uid();
    if scope_owner != socket_owner {
        return Err("native_resident_socket_dir_owner_mismatch".to_owned());
    }
    Ok(directory)
}

fn state_message(state: &ResidentState) -> Vec<u8> {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        state.schema,
        state.generation,
        state.process_id,
        state.owner_process_id,
        state.runtime_sha256,
        state.transport,
        state.endpoint,
        state.token_hex,
        state.created_ms,
    )
    .into_bytes()
}

fn state_mac(state: &ResidentState, token: &[u8]) -> String {
    hex_bytes(&crate::hmac_sha256(
        token,
        STATE_MAC_LABEL,
        &state_message(state),
    ))
}

pub(crate) fn token_from_state(state: &ResidentState) -> Result<Vec<u8>, String> {
    let token = decode_hex(&state.token_hex)?;
    if token.len() != crate::AUTH_TOKEN_BYTES {
        return Err("native_resident_state_token_invalid".to_owned());
    }
    Ok(token)
}

fn validate_state(
    scope: &Path,
    state: &ResidentState,
    expected_digest: &str,
) -> Result<(), String> {
    #[cfg(not(unix))]
    let _ = scope;
    if state.schema != STATE_SCHEMA
        || state.generation == 0
        || state.process_id == 0
        || state.owner_process_id == 0
        || state.runtime_sha256 != expected_digest
        || !matches!(state.transport.as_str(), "unix" | "loopback")
        || state.endpoint.len() > 32 * 1024
    {
        return Err("native_resident_state_invalid".to_owned());
    }
    if state.transport == "unix" {
        #[cfg(not(unix))]
        return Err("native_resident_state_transport_invalid".to_owned());
        #[cfg(unix)]
        {
            let endpoint = Path::new(&state.endpoint);
            let scoped_parent = endpoint.parent() == Some(scope);
            let compact_parent = socket_directory_path(scope, expected_digest).as_path()
                == endpoint.parent().unwrap_or_else(|| Path::new(""))
                && endpoint.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with(&format!("h3-{}-", &expected_digest[..8]))
                });
            if !scoped_parent && !compact_parent {
                return Err("native_resident_state_endpoint_invalid".to_owned());
            }
        }
    }
    let token = token_from_state(state)?;
    let expected = state_mac(state, &token);
    if !crate::constant_time_eq(expected.as_bytes(), state.state_mac.as_bytes()) {
        return Err("native_resident_state_mac_invalid".to_owned());
    }
    Ok(())
}

fn read_state_file(
    path: &Path,
    scope: &Path,
    expected_digest: &str,
) -> Result<ResidentState, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "native_resident_state_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_STATE_BYTES
    {
        return Err("native_resident_state_invalid".to_owned());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| "native_resident_state_read_failed".to_owned())?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("native_resident_state_invalid".to_owned());
    }
    let value =
        crate::strict_json_value(&bytes).map_err(|_| "native_resident_state_invalid".to_owned())?;
    let state = serde_json::from_value::<ResidentState>(value)
        .map_err(|_| "native_resident_state_invalid".to_owned())?;
    validate_state(scope, &state, expected_digest)?;
    Ok(state)
}

pub(crate) fn discover_states(
    scope: &Path,
    expected_digest: &str,
) -> Result<Vec<ResidentState>, String> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(scope).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        let entry = entry.map_err(|_| "native_resident_state_list_failed".to_owned())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(STATE_FILE_PREFIX) && name.ends_with(STATE_FILE_SUFFIX) {
            paths.push(entry.path());
            if paths.len() > MAX_STATE_FILES {
                paths.sort_unstable_by(|left, right| right.file_name().cmp(&left.file_name()));
                paths.truncate(MAX_STATE_FILES);
            }
        }
    }
    let mut states = Vec::new();
    for path in paths {
        if let Ok(state) = read_state_file(&path, scope, expected_digest) {
            states.push(state);
        }
    }
    states.sort_by_key(|state| std::cmp::Reverse(state.generation));
    Ok(states)
}

pub(crate) fn next_generation(scope: &Path, digest: &str) -> Result<u64, String> {
    let highest = discover_states(scope, digest)?
        .into_iter()
        .find(|state| validate_package_process_identity(state.process_id).is_ok())
        .map(|state| state.generation)
        .unwrap_or(0);
    Ok(now_ms()?.max(highest.saturating_add(1)).max(1))
}

pub(crate) fn publish_state(
    scope: &Path,
    generation: u64,
    owner_process_id: u32,
    digest: &str,
    transport: &str,
    endpoint: String,
    token: &[u8],
) -> Result<ResidentState, String> {
    let mut state = ResidentState {
        schema: STATE_SCHEMA.to_owned(),
        generation,
        process_id: std::process::id(),
        owner_process_id,
        runtime_sha256: digest.to_owned(),
        transport: transport.to_owned(),
        endpoint,
        token_hex: hex_bytes(token),
        created_ms: now_ms()?,
        state_mac: String::new(),
    };
    state.state_mac = state_mac(&state, token);
    let path = scope.join(format!(
        "{STATE_FILE_PREFIX}{generation:020}{STATE_FILE_SUFFIX}"
    ));
    let encoded =
        serde_json::to_vec(&state).map_err(|_| "native_resident_state_encode_failed".to_owned())?;
    let mut file = private_file(&path, true)?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_state_write_failed".to_owned())?;
    let retained_generations = discover_states(scope, digest)?
        .into_iter()
        .filter(|candidate| {
            validate_package_process_identity(candidate.process_id).is_ok()
                && validate_package_process_identity(candidate.owner_process_id).is_ok()
        })
        .take(RETAINED_STATE_FILES)
        .map(|candidate| candidate.generation)
        .collect::<std::collections::HashSet<_>>();
    let superseded = fs::read_dir(scope)
        .map_err(|_| "native_resident_state_list_failed".to_owned())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with(STATE_FILE_PREFIX) && name.ends_with(STATE_FILE_SUFFIX)
            })
        })
        .collect::<Vec<_>>();
    for candidate in superseded {
        let generation = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(STATE_FILE_PREFIX))
            .and_then(|name| name.strip_suffix(STATE_FILE_SUFFIX))
            .and_then(|name| name.parse::<u64>().ok());
        if generation.is_some_and(|value| retained_generations.contains(&value)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|_| "native_resident_state_stat_failed".to_owned())?;
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            fs::remove_file(candidate)
                .map_err(|_| "native_resident_state_prune_failed".to_owned())?;
        }
    }
    Ok(state)
}

pub(crate) fn acquire_startup_lock(scope: &Path) -> Result<Option<StartupLock>, String> {
    let path = scope.join("startup.lock");
    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(|_| "native_client_random_failed".to_owned())?;
    let nonce = format!("{}:{}", std::process::id(), hex_bytes(&nonce_bytes));
    match private_file(&path, true) {
        Ok(mut file) => {
            file.write_all(nonce.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| "native_resident_lock_write_failed".to_owned())?;
            Ok(Some(StartupLock { path, nonce }))
        }
        Err(_) => Ok(None),
    }
}

pub(crate) fn clear_stale_startup_lock(
    scope: &Path,
    _expected_digest: &str,
) -> Result<bool, String> {
    let path = scope.join("startup.lock");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("native_resident_lock_stat_failed".to_owned()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("native_resident_lock_invalid".to_owned());
    }
    let age = metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    if age.is_none_or(|age| age < LOCK_STALE_AFTER) {
        return Ok(false);
    }
    let contents =
        fs::read_to_string(&path).map_err(|_| "native_resident_lock_read_failed".to_owned())?;
    let owner_process_id = contents
        .split_once(':')
        .and_then(|(process_id, nonce)| {
            if nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                process_id.parse::<u32>().ok()
            } else {
                None
            }
        })
        .filter(|process_id| *process_id > 0);
    if owner_process_id
        .is_some_and(|process_id| validate_package_process_identity(process_id).is_ok())
    {
        return Ok(false);
    }
    fs::remove_file(path).map_err(|_| "native_resident_lock_recovery_failed".to_owned())?;
    Ok(true)
}

#[cfg(test)]
#[path = "resident_state_tests.rs"]
mod tests;
