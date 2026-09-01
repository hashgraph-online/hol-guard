#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use crate::resident_state::{ensure_private_directory, process_start_marker};

const LEASE_DIRECTORY: &str = "resident-client-leases.v1";
const LEASE_PREFIX: &str = "client-";
const LEASE_SUFFIX: &str = ".lease";
const LEASE_MAX_BYTES: u64 = 512;
const LEASE_MAX_FILES: usize = 64;
const LEASE_HEARTBEAT: Duration = Duration::from_millis(250);
pub(super) const LEASE_EXPIRY: Duration = Duration::from_secs(1);

pub(super) struct ClientLease {
    path: PathBuf,
    stopped: Arc<AtomicBool>,
    heartbeat: Option<thread::JoinHandle<()>>,
}

impl Drop for ClientLease {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

fn lease_directory(state_base: &Path) -> Result<PathBuf, String> {
    let base = ensure_private_directory(state_base, false)?;
    ensure_private_directory(&base.join(LEASE_DIRECTORY), true)
}

pub(super) fn acquire(state_base: &Path) -> Result<ClientLease, String> {
    let directory = lease_directory(state_base)?;
    let process_id = std::process::id();
    let start_marker = process_start_marker(process_id)?;
    let digest = crate::resident_state::runtime_digest()?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "native_client_random_failed".to_owned())?;
    let nonce = crate::resident_state_encoding::hex_bytes(&nonce);
    let path = directory.join(format!("{LEASE_PREFIX}{process_id}-{nonce}{LEASE_SUFFIX}"));
    let contents = format!("{process_id}\n{start_marker}\n{digest}\n");
    let mut file = crate::resident_state::private_file(&path, true)?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_lease_write_failed".to_owned())?;
    let stopped = Arc::new(AtomicBool::new(false));
    let heartbeat_stopped = Arc::clone(&stopped);
    let heartbeat_path = path.clone();
    let heartbeat_contents = contents.clone();
    let heartbeat = thread::spawn(move || {
        while !heartbeat_stopped.load(Ordering::Acquire) {
            thread::sleep(LEASE_HEARTBEAT);
            if heartbeat_stopped.load(Ordering::Acquire) {
                break;
            }
            let Ok(mut file) = crate::resident_state::private_file(&heartbeat_path, false) else {
                break;
            };
            if file
                .write_all(heartbeat_contents.as_bytes())
                .and_then(|()| file.sync_all())
                .is_err()
            {
                break;
            }
        }
    });
    Ok(ClientLease {
        path,
        stopped,
        heartbeat: Some(heartbeat),
    })
}

fn lease_is_live(path: &Path, expected_digest: Option<&str>) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > LEASE_MAX_BYTES
    {
        return false;
    }
    if metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_none_or(|age| age > LEASE_EXPIRY)
    {
        return false;
    }
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    let mut lines = contents.lines();
    let Some(process_id) = lines.next().and_then(|value| value.parse::<u32>().ok()) else {
        return false;
    };
    let Some(start_marker) = lines.next().filter(|value| !value.is_empty()) else {
        return false;
    };
    let Some(digest) = lines.next().filter(|value| value.len() == 64) else {
        return false;
    };
    if !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || expected_digest.is_some_and(|expected| digest != expected)
    {
        return false;
    }
    process_start_marker(process_id).is_ok_and(|actual| actual == start_marker)
}

fn any_live_with_digest(state_base: &Path, expected_digest: Option<&str>) -> bool {
    let Ok(directory) = lease_directory(state_base) else {
        return false;
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };
    entries
        .filter_map(Result::ok)
        .take(LEASE_MAX_FILES)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            (name.starts_with(LEASE_PREFIX) && name.ends_with(LEASE_SUFFIX)).then_some(entry.path())
        })
        .any(|path| lease_is_live(&path, expected_digest))
}

#[cfg(test)]
pub(super) fn any_live(state_base: &Path, expected_digest: &str) -> bool {
    any_live_with_digest(state_base, Some(expected_digest))
}

pub(super) fn any_live_for_home(state_base: &Path) -> bool {
    any_live_with_digest(state_base, None)
}
