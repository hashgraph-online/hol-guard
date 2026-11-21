//! The advisory lock shared by writers of policy-integrity generations.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::resident_state::is_lock_contention;

pub(crate) const LOCK_FILE: &str = "policy-integrity-generation.lock";
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_POLL: Duration = Duration::from_millis(50);

pub(crate) fn acquire(home: &Path, wait: Duration) -> Option<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(home.join(LOCK_FILE)).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let deadline = Instant::now().checked_add(wait)?;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Some(file),
            Err(error) if is_lock_contention(&error) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return None;
                }
                std::thread::sleep(remaining.min(LOCK_POLL));
            }
            Err(_) => return None,
        }
    }
}
