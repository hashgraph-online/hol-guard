//! The shared storage gate the evidence store holds around one store call,
//! ported from `store_storage_gate` rather than called through Python.

use std::fs::File;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use fs2::FileExt;

/// `store_storage_gate._GATE_FILE_NAME`.
pub(crate) const STORAGE_GATE_FILE_NAME: &str = "storage-access.lock";
/// `hold_storage_gate` retries a contended gate on this interval
/// (`time.sleep(0.01)`).
const GATE_POLL: Duration = Duration::from_millis(10);

/// `hold_storage_gate(guard_home)` — a shared hold that waits for an
/// exclusive maintenance hold to end, creating the gate file when the home has
/// never taken one.
///
/// The daemon's hook path takes this gate try-once on a file that must already
/// exist, because a hook that cannot have it immediately defers to the daemon.
/// The writer has nothing to defer to, so it waits like Python does.
pub(crate) fn hold_storage_gate(guard_home: &Path, wait: Duration) -> Result<File, io::Error> {
    let gate = open_gate(&guard_home.join(STORAGE_GATE_FILE_NAME))?;
    let deadline = Instant::now() + wait;
    loop {
        match FileExt::try_lock_shared(&gate) {
            Ok(()) => return Ok(gate),
            Err(error) if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for the Guard storage gate: {error}"),
                ))
            }
            Err(_) => std::thread::sleep(GATE_POLL),
        }
    }
}

/// The gate opened without following a link at the leaf, created private when
/// it is not there yet.
#[cfg(unix)]
fn open_gate(path: &Path) -> Result<File, io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Python takes the gate with `msvcrt.locking` on its first byte, which has no
/// shared mode; the shared whole-file `LockFileEx` here still excludes that
/// hold and any exclusive one.
#[cfg(windows)]
fn open_gate(path: &Path) -> Result<File, io::Error> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the Guard storage gate is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_gate(_path: &Path) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Guard storage gate needs file locking",
    ))
}
