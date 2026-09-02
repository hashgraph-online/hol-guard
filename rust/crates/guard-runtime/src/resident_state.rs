#![forbid(unsafe_code)]

use crate::resident_state_encoding::{decode_hex, hex_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "resident_startup_lock.rs"]
mod resident_startup_lock;
#[path = "resident_state_discovery.rs"]
mod resident_state_discovery;
#[path = "resident_state_files.rs"]
mod resident_state_files;

#[allow(unused_imports)]
pub(crate) use resident_startup_lock::{
    acquire_startup_lock, clear_stale_startup_lock, StartupLock,
};
#[cfg(all(windows, test))]
pub(crate) use resident_state_files::bind_windows_private_directory;
#[cfg(any(not(windows), test))]
#[allow(unused_imports)]
pub(crate) use resident_state_files::ensure_private_directory;
#[cfg(windows)]
#[allow(unused_imports)]
pub(crate) use resident_state_files::{
    bind_windows_existing_directory, open_private_read, protect_windows_private_path,
    remove_windows_private_file, replace_windows_private_file, verify_windows_private_file,
    verify_windows_private_path,
};
#[allow(unused_imports)]
pub(crate) use resident_state_files::{
    ensure_private_directory_under, is_lock_contention, private_file, private_lock_file,
};

const STATE_SCHEMA: &str = "hol-guard-resident-state.v3";
const STATE_FILE_PREFIX: &str = "generation-";
const STATE_FILE_SUFFIX: &str = ".json";
const STATE_MAC_LABEL: &[u8] = b"hol-guard-resident-state-v3\0";
const MAX_STATE_BYTES: u64 = 16 * 1024;
const MAX_STATE_FILES: usize = 64;
const RETAINED_STATE_FILES: usize = 8;
const MAX_RUNTIME_BYTES: u64 = 128 * 1024 * 1024;
const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);
const MAX_STARTUP_LOCK_BYTES: u64 = 4 * 1024;

#[allow(unused_imports)]
pub(crate) use resident_state_discovery::{discover_home_states, discover_home_states_prefer};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentState {
    pub(crate) schema: String,
    pub(crate) generation: u64,
    pub(crate) process_id: u32,
    pub(crate) process_start_marker: String,
    pub(crate) owner_process_id: u32,
    pub(crate) owner_process_start_marker: String,
    pub(crate) runtime_sha256: String,
    pub(crate) transport: String,
    pub(crate) endpoint: String,
    pub(crate) token_hex: String,
    pub(crate) created_ms: u64,
    pub(crate) state_mac: String,
}

fn now_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "native_resident_clock_invalid".to_owned())
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
    static RUNTIME_DIGEST: OnceLock<Result<String, String>> = OnceLock::new();
    RUNTIME_DIGEST
        .get_or_init(|| {
            let executable = std::env::current_exe()
                .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
            executable_digest(&executable)
        })
        .clone()
}

pub(crate) use crate::resident_process_identity::{
    parent_process_id, process_start_marker, validate_package_process_identity,
    validate_runtime_process_identity,
};

pub(crate) fn state_scope(base: &Path, digest: &str) -> Result<PathBuf, String> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native_resident_runtime_digest_invalid".to_owned());
    }
    let private_root = private_root_for_state_base(base)?;
    let base = ensure_private_directory_under(base, &private_root, false)?;
    ensure_private_directory_under(
        &base.join(format!("resident-v3-{}", &digest[..16])),
        &private_root,
        true,
    )
}

/// Return the already-private guard-home root for a native runtime state base.
/// Production state lives at `<guard-home>/native-runtime`; test fixtures may
/// use the state base itself as their private root.
pub(crate) fn private_root_for_state_base(state_base: &Path) -> Result<PathBuf, String> {
    if state_base
        .file_name()
        .is_some_and(|name| name == "native-runtime")
    {
        return state_base
            .parent()
            .map(Path::to_owned)
            .ok_or_else(|| "native_resident_private_root_missing".to_owned());
    }
    Ok(state_base.to_owned())
}

pub(crate) fn private_root_for_scope(scope: &Path) -> Result<PathBuf, String> {
    let state_base = scope
        .parent()
        .ok_or_else(|| "native_resident_private_root_missing".to_owned())?;
    private_root_for_state_base(state_base)
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
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        state.schema,
        state.generation,
        state.process_id,
        state.process_start_marker,
        state.owner_process_id,
        state.owner_process_start_marker,
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
        || state.process_start_marker.is_empty()
        || state.owner_process_start_marker.is_empty()
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

fn read_state_file_raw(path: &Path, private_root: &Path) -> Result<ResidentState, String> {
    #[cfg(not(windows))]
    let _ = private_root;
    #[cfg(windows)]
    let file =
        resident_state_files::open_private_read(path, MAX_STATE_BYTES, "state", private_root)?
            .ok_or_else(|| "native_resident_state_stat_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "native_resident_state_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_STATE_BYTES
        {
            return Err("native_resident_state_invalid".to_owned());
        }
        #[cfg(unix)]
        let mut options = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options
        };
        #[cfg(not(unix))]
        let mut options = OpenOptions::new();
        options.read(true);
        options
            .open(path)
            .map_err(|_| "native_resident_state_read_failed".to_owned())?
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_resident_state_read_failed".to_owned())?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("native_resident_state_invalid".to_owned());
    }
    let value =
        crate::strict_json_value(&bytes).map_err(|_| "native_resident_state_invalid".to_owned())?;
    let state = serde_json::from_value::<ResidentState>(value)
        .map_err(|_| "native_resident_state_invalid".to_owned())?;
    Ok(state)
}

fn read_state_file(
    path: &Path,
    scope: &Path,
    expected_digest: &str,
) -> Result<ResidentState, String> {
    let private_root = private_root_for_scope(scope)?;
    let state = read_state_file_raw(path, &private_root)?;
    validate_state(scope, &state, expected_digest)?;
    Ok(state)
}

pub(crate) fn discover_states(
    scope: &Path,
    expected_digest: &str,
) -> Result<Vec<ResidentState>, String> {
    let paths = resident_state_discovery::state_paths(scope)?;
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
        .find(|state| {
            validate_package_process_identity(state.process_id, &state.process_start_marker).is_ok()
        })
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
    let process_id = std::process::id();
    let serving_start_marker = process_start_marker(process_id)?;
    let owner_process_start_marker = process_start_marker(owner_process_id)?;
    let mut state = ResidentState {
        schema: STATE_SCHEMA.to_owned(),
        generation,
        process_id,
        process_start_marker: serving_start_marker,
        owner_process_id,
        owner_process_start_marker,
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
    let private_root = private_root_for_scope(scope)?;
    let mut file = private_file(&path, true, &private_root)?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_state_write_failed".to_owned())?;
    let retained_generations = discover_states(scope, digest)?
        .into_iter()
        .filter(|candidate| {
            validate_package_process_identity(candidate.process_id, &candidate.process_start_marker)
                .is_ok()
                && validate_package_process_identity(
                    candidate.owner_process_id,
                    &candidate.owner_process_start_marker,
                )
                .is_ok()
        })
        .take(RETAINED_STATE_FILES)
        .map(|candidate| candidate.generation)
        .collect::<std::collections::HashSet<_>>();
    let superseded = resident_state_discovery::state_paths(scope)?;
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
        #[cfg(windows)]
        if remove_windows_private_file(&candidate, &private_root).is_err() {
            match fs::remove_file(&candidate) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("native_resident_state_prune_failed".to_owned()),
            }
        }
        #[cfg(not(windows))]
        {
            let metadata = fs::symlink_metadata(&candidate)
                .map_err(|_| "native_resident_state_stat_failed".to_owned())?;
            if metadata.is_file() && !metadata.file_type().is_symlink() {
                fs::remove_file(candidate)
                    .map_err(|_| "native_resident_state_prune_failed".to_owned())?;
            }
        }
    }
    Ok(state)
}

#[cfg(test)]
#[path = "resident_state_tests.rs"]
mod tests;
