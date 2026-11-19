//! `codex_install_transaction` and `codex_lifecycle_lock`: the resident holds
//! the Codex lock files.
//!
//! A client asks for one lock with its process id. The resident opens and
//! checks the lock file, takes the exclusive advisory lock without waiting,
//! and keeps the handle under a lease until the client releases it or the
//! client process is gone. A busy lock answers `busy` at once; the client
//! retries until its own deadline, so no resident worker sleeps on a lock.
//! While any lease is held, one reaper thread checks every 50 ms that each
//! client is still running and releases the locks of those that are gone, so
//! a client killed mid-operation frees its lock for clients of other
//! residents too.
//!
//! `owned` composes these leases into one owner's installation transaction.
//!
//! Three locks exist; `lock_files` opens and checks them. The installation lock is `managed/codex/installation.lock`
//! under a Guard home, in a private directory repaired to owner-only. A
//! lifecycle lock is one file per Codex configuration directory, under the
//! account's own home as the operating system reports it, so a CLI and the
//! Desktop app agree even when their environments differ. The OpenCode lock
//! serializes Guard's readers and writers of one home's OpenCode config.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::lock_files::{
    identity, install_lock, lifecycle_lock, link_count, opencode_lock, Refusal,
};
use crate::resident_process_identity::running_process_start_marker;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_LEASES: usize = 256;

struct Lease {
    file: fs::File,
    path: PathBuf,
    pid: u32,
    marker: String,
}

static LEASES: Mutex<Option<HashMap<String, Lease>>> = Mutex::new(None);
/// Set while the reaper runs; read and written only under `LEASES`.
static REAPER: AtomicBool = AtomicBool::new(false);
const REAP_INTERVAL: Duration = Duration::from_millis(50);

fn contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
        || (cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33)))
}

/// Python's `msvcrt.locking` needs a byte to lock, so an empty Windows lock
/// file gets one first.
pub(super) fn try_lock(file: &mut fs::File) -> std::io::Result<bool> {
    #[cfg(windows)]
    {
        use std::io::Write;
        if file.metadata()?.len() == 0 {
            file.write_all(b"0")?;
            file.flush()?;
        }
    }
    match fs2::FileExt::try_lock_exclusive(&*file) {
        Ok(()) => Ok(true),
        Err(error) if contended(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The OpenCode config lock held by the caller's own handle for one native
/// call, waiting up to `wait` while another Guard operation holds it. Answers
/// `opencode_config_busy` when it stays busy and the lock file's refusal
/// reason when the file cannot be opened safely.
pub(crate) fn hold_opencode_lock(home_dir: &Path, wait: Duration) -> Result<fs::File, String> {
    let (file, _) = opencode_lock(home_dir).map_err(|refusal| refusal.0)?;
    hold(file, wait, "opencode_config_busy")
}

/// The Guard home's installation lock held by the caller's own handle, so a
/// resident stop neither interrupts an install that holds its lease nor lets
/// one start until the stop is done. Answers
/// `native_resident_install_in_progress` when an install keeps it past `wait`.
pub(crate) fn hold_install_lock(guard_home: &Path, wait: Duration) -> Result<fs::File, String> {
    let (file, _) = install_lock(guard_home).map_err(|refusal| refusal.0)?;
    hold(file, wait, "native_resident_install_in_progress")
}

fn hold(mut file: fs::File, wait: Duration, busy: &str) -> Result<fs::File, String> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        match try_lock(&mut file) {
            Ok(true) => return Ok(file),
            Ok(false) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(false) => return Err(busy.to_owned()),
            Err(error) => return Err(Refusal::lifecycle("lock", &error).0),
        }
    }
}

/// Drop every lease whose client process is gone, releasing its lock.
fn reap(leases: &mut HashMap<String, Lease>) {
    leases.retain(|_, lease| {
        running_process_start_marker(lease.pid).is_ok_and(|marker| marker == lease.marker)
    });
}

/// Start the reaper unless it runs. The caller holds `LEASES`, so the
/// reaper cannot stop between this check and the new lease.
fn ensure_reaper() {
    if REAPER.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("codex-lease-reaper".into())
        .spawn(|| loop {
            std::thread::sleep(REAP_INTERVAL);
            let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
            let leases = guard.get_or_insert_with(HashMap::new);
            reap(leases);
            if leases.is_empty() {
                REAPER.store(false, Ordering::SeqCst);
                return;
            }
        });
    if spawned.is_err() {
        // The next acquire tries again; calls still reap on their own.
        REAPER.store(false, Ordering::SeqCst);
    }
}

fn token() -> Result<String, &'static str> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ERR_INVALID)?;
    Ok(hex::encode(bytes))
}

fn acquire(args: &Map<String, Value>) -> KindResult {
    let pid = args
        .get("client_pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or(ERR_INVALID)?;
    let marker = running_process_start_marker(pid).map_err(|_| ERR_INVALID)?;
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let opened = match text("lock")? {
        "install" => install_lock(Path::new(text("guard_home")?)),
        "lifecycle" => lifecycle_lock(Path::new(text("directory")?)),
        "opencode" => opencode_lock(Path::new(text("home_dir")?)),
        _ => return Err(ERR_INVALID),
    };
    let (mut file, path) = match opened {
        Ok(opened) => opened,
        Err(Refusal(error)) => return Ok(json!({ "ok": false, "error": error })),
    };
    let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
    let leases = guard.get_or_insert_with(HashMap::new);
    reap(leases);
    if leases.len() >= MAX_LEASES {
        return Ok(json!({ "ok": false, "busy": true }));
    }
    match try_lock(&mut file) {
        Ok(true) => {}
        Ok(false) => return Ok(json!({ "ok": false, "busy": true })),
        Err(error) => {
            let Refusal(error) = Refusal::lifecycle("file", &error);
            return Ok(json!({ "ok": false, "error": error }));
        }
    }
    let lease = token()?;
    leases.insert(
        lease.clone(),
        Lease {
            file,
            path,
            pid,
            marker,
        },
    );
    ensure_reaper();
    Ok(json!({ "ok": true, "lease": lease }))
}

/// Register a lock this caller already holds under a lease for the client
/// process `pid`, so the reaper frees it if that process is gone.
pub(super) fn adopt(file: fs::File, path: PathBuf, pid: u32) -> Result<String, &'static str> {
    let marker = running_process_start_marker(pid).map_err(|_| ERR_INVALID)?;
    let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
    let leases = guard.get_or_insert_with(HashMap::new);
    reap(leases);
    if leases.len() >= MAX_LEASES {
        return Err(ERR_INVALID);
    }
    let lease = token()?;
    leases.insert(
        lease.clone(),
        Lease {
            file,
            path,
            pid,
            marker,
        },
    );
    ensure_reaper();
    Ok(lease)
}

/// Close the lease's handle, releasing its advisory lock.
pub(super) fn release(lease: &str) {
    let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
    let leases = guard.get_or_insert_with(HashMap::new);
    leases.remove(lease);
    reap(leases);
}

/// Whether the lease is live and its lock file is still the one at the path.
pub(super) fn held(lease: &str) -> bool {
    let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
    let leases = guard.get_or_insert_with(HashMap::new);
    reap(leases);
    leases.get(lease).is_some_and(check)
}

/// Whether the lease is live and holds the lock file at `path`, not another lock's.
pub(super) fn held_at(lease: &str, path: &Path) -> bool {
    let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
    let leases = guard.get_or_insert_with(HashMap::new);
    reap(leases);
    leases
        .get(lease)
        .is_some_and(|lease| lease.path == path && check(lease))
}

/// `check`: the lease is live and its lock file is still the one at the path.
fn check(lease: &Lease) -> bool {
    let (Ok(opened), Ok(current)) = (lease.file.metadata(), fs::symlink_metadata(&lease.path))
    else {
        return false;
    };
    current.is_file() && link_count(&current) == 1 && identity(&opened) == identity(&current)
}

pub(super) fn dispatch(op: &str, args: &Map<String, Value>) -> KindResult {
    if op == "lease_acquire" {
        return acquire(args);
    }
    let lease = args
        .get("lease")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let mut guard = LEASES.lock().unwrap_or_else(PoisonError::into_inner);
    let leases = guard.get_or_insert_with(HashMap::new);
    match op {
        "lease_release" => {
            // Closing the handle releases the advisory lock.
            let released = leases.remove(lease).is_some();
            reap(leases);
            Ok(json!({ "ok": true, "released": released }))
        }
        "lease_check" => {
            reap(leases);
            let held = leases.get(lease).is_some_and(check);
            Ok(json!({ "ok": true, "held": held }))
        }
        _ => Err(ERR_INVALID),
    }
}
