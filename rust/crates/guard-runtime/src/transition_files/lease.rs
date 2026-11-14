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
//! Two locks exist. The installation lock is `managed/codex/installation.lock`
//! under a Guard home, in a private directory repaired to owner-only. A
//! lifecycle lock is one file per Codex configuration directory, under the
//! account's own home as the operating system reports it, so a CLI and the
//! Desktop app agree even when their environments differ.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::inspect::{resolve_lenient, sha256_hex};
use crate::resident_process_identity::running_process_start_marker;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_LEASES: usize = 256;
const LIFECYCLE_BASE: &str = ".hol-guard-codex-lifecycle-locks";
const INSTALL_UNSAFE: &str = "codex_hook_transaction_lock_unsafe";

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

/// A refusal the client raises as its own error type.
struct Refusal(String);

impl Refusal {
    fn lifecycle(stage: &str, error: &std::io::Error) -> Self {
        let reason = error
            .raw_os_error()
            .and_then(errno_name)
            .unwrap_or("UNKNOWN");
        Self(format!(
            "codex_lifecycle_lock_invalid: lifecycle lock {stage} is unavailable (reason={reason})"
        ))
    }
}

/// `errno.errorcode` for the reasons a lock file can be refused with.
fn errno_name(code: i32) -> Option<&'static str> {
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        Some(match Errno::from_raw(code) {
            Errno::EACCES => "EACCES",
            Errno::EPERM => "EPERM",
            Errno::ENOENT => "ENOENT",
            Errno::ELOOP => "ELOOP",
            Errno::ENOTDIR => "ENOTDIR",
            Errno::EROFS => "EROFS",
            Errno::ENOSPC => "ENOSPC",
            Errno::EEXIST => "EEXIST",
            Errno::EISDIR => "EISDIR",
            Errno::EMFILE => "EMFILE",
            Errno::ENAMETOOLONG => "ENAMETOOLONG",
            _ => return None,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = code;
        None
    }
}

fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        (0, 0)
    }
}

fn link_count(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        1
    }
}

fn reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn owned_privately(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn open_lock(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    options.open(path)
}

/// `_ensure_private_directory(..., repair_mode=True)`.
fn private_directory(path: &Path) -> Result<(), Refusal> {
    let refuse = |code: &str| Refusal(code.to_owned());
    fs::create_dir_all(path).map_err(|_| refuse("codex_hook_manifest_directory_unsafe"))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| refuse("codex_hook_manifest_directory_unsafe"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(refuse("codex_hook_manifest_directory_unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(refuse("codex_hook_manifest_directory_owner_mismatch"));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| refuse("codex_hook_manifest_directory_permissions_unsafe"))?;
        }
    }
    Ok(())
}

/// The installation lock, opened and checked as `_verify_lock_file` does.
fn install_lock(guard_home: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let path = resolve_lenient(guard_home)
        .join("managed")
        .join("codex")
        .join("installation.lock");
    let parent = path.parent().ok_or(Refusal(INSTALL_UNSAFE.to_owned()))?;
    private_directory(parent)?;
    let unsafe_lock = |_| Refusal(INSTALL_UNSAFE.to_owned());
    let file = open_lock(&path).map_err(unsafe_lock)?;
    let opened = file.metadata().map_err(unsafe_lock)?;
    let current = fs::symlink_metadata(&path).map_err(unsafe_lock)?;
    if !opened.is_file()
        || !current.is_file()
        || link_count(&opened) != 1
        || identity(&opened) != identity(&current)
        || reparse(&current)
        || !owned_privately(&opened)
    {
        return Err(Refusal(INSTALL_UNSAFE.to_owned()));
    }
    Ok((file, path))
}

fn account_home() -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|user| user.dir)
            .ok_or_else(|| std::io::Error::other("codex_lifecycle_account_home_unavailable"))
    }
    #[cfg(windows)]
    {
        guard_runtime_windows_process::user_profile_directory()
            .and_then(|profile| {
                guard_runtime_windows_process::real_directory(&profile.to_string_lossy())
            })
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other("codex_lifecycle_account_home_unavailable"))
    }
}

/// `os.path.normcase(str(directory.resolve()))`.
fn configuration_identity(directory: &Path) -> String {
    let resolved = resolve_lenient(directory).to_string_lossy().into_owned();
    if cfg!(windows) {
        resolved.replace('/', "\\").to_lowercase()
    } else {
        resolved
    }
}

fn lifecycle_identity(path: &Path) -> Result<Option<(u64, u64)>, Refusal> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Refusal::lifecycle("file", &error)),
        Ok(metadata) if !metadata.is_file() || link_count(&metadata) != 1 => Err(Refusal(
            "codex_lifecycle_lock_invalid: lifecycle lock must be a regular file with one link"
                .to_owned(),
        )),
        Ok(metadata) => Ok(Some(identity(&metadata))),
    }
}

/// `codex_lifecycle_lock._target_lock`: open and check one lifecycle lock.
fn lifecycle_lock(directory: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let base = account_home()
        .map_err(|error| Refusal::lifecycle("directory", &error))?
        .join(LIFECYCLE_BASE);
    lifecycle_lock_in(&base, directory)
}

fn lifecycle_lock_in(base: &Path, directory: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let path = base.join(format!(
        "{}.lock",
        sha256_hex(configuration_identity(directory).as_bytes())
    ));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(error) = builder.create(base) {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(Refusal::lifecycle("directory", &error));
        }
    }
    let metadata =
        fs::symlink_metadata(base).map_err(|error| Refusal::lifecycle("directory", &error))?;
    let private = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            metadata.uid() == nix::unistd::getuid().as_raw()
                && metadata.permissions().mode() & 0o077 == 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    if !metadata.is_dir() || !private {
        return Err(Refusal(
            "codex_lifecycle_lock_invalid: lifecycle lock directory is not private".to_owned(),
        ));
    }
    let prior = lifecycle_identity(&path)?;
    let file = open_lock(&path).map_err(|error| Refusal::lifecycle("file", &error))?;
    let opened = file
        .metadata()
        .map_err(|error| Refusal::lifecycle("file", &error))?;
    let opened = identity(&opened);
    if lifecycle_identity(&path)? != Some(opened) || prior.is_some_and(|prior| prior != opened) {
        return Err(Refusal(
            "codex_lifecycle_lock_invalid: lifecycle lock changed while opening".to_owned(),
        ));
    }
    Ok((file, path))
}

fn contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
        || (cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33)))
}

/// Python's `msvcrt.locking` needs a byte to lock, so an empty Windows lock
/// file gets one first.
fn try_lock(file: &mut fs::File) -> std::io::Result<bool> {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_lock_refuses_a_linked_file_and_keeps_its_target() {
        let root = tempfile::TempDir::new().unwrap();
        let base = root.path().join("locks");
        let directory = root.path().join("home/.codex");
        let (_, path) = lifecycle_lock_in(&base, &directory).ok().unwrap();
        fs::remove_file(&path).unwrap();
        let target = base.join("user-file");
        fs::write(&target, b"kept").unwrap();
        fs::hard_link(&target, &path).unwrap();
        let Err(Refusal(error)) = lifecycle_lock_in(&base, &directory) else {
            panic!("linked lock accepted");
        };
        assert!(error.starts_with("codex_lifecycle_lock_invalid"), "{error}");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(lifecycle_lock_in(&base, &directory).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"kept");
    }
}
