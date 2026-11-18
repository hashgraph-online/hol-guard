//! The native daemon's standard error, kept in a private file under the
//! Guard home instead of the null device, so the message a daemon prints as
//! it fails (a listener error, a state it could not publish) is still there
//! when someone looks for why it stopped.
//!
//! The file is opened by the launcher and handed to the daemon. It is rotated
//! at launch once it reaches `MAX_STDERR_BYTES`, keeping one previous file.
//! Any problem opening it falls back to the null device: a daemon must never
//! fail to start for want of a log.

use std::fs::File;
use std::path::Path;
use std::process::Stdio;

use crate::runtime_output_directory::LogDirectory;

const LOG_DIRECTORY: &str = "logs";
const STDERR_LOG: &str = "daemon-serve.stderr";
const ROTATED_STDERR_LOG: &str = "daemon-serve.stderr.1";
const MAX_STDERR_BYTES: u64 = 1024 * 1024;

/// Standard error for a native daemon of `home`.
pub(super) fn daemon_stderr(home: &Path) -> Stdio {
    open_stderr_log(home).map_or_else(Stdio::null, Stdio::from)
}

/// The log is opened through its directory's descriptor, without following
/// a link and without waiting on a FIFO, and kept only if it is a regular,
/// owner-only file; anything else falls back to the null device.
///
/// The current log is opened, and so made owner-only, before it is rotated,
/// so the kept copy is never left readable by others.
fn open_stderr_log(home: &Path) -> Option<File> {
    let directory = LogDirectory::open(home, LOG_DIRECTORY)?;
    let current = directory.open_file(STDERR_LOG, true)?;
    if current.metadata().ok()?.len() < MAX_STDERR_BYTES {
        return Some(current);
    }
    drop(current);
    directory.rename(STDERR_LOG, ROTATED_STDERR_LOG)?;
    directory.open_file(STDERR_LOG, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn the_log_is_private_and_rotates_at_launch() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(LOG_DIRECTORY).join(STDERR_LOG);
        drop(open_stderr_log(home.path()).expect("stderr log"));
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let directory = fs::metadata(path.parent().unwrap()).unwrap();
            assert_eq!(directory.permissions().mode() & 0o777, 0o700);
        }
        fs::write(&path, vec![b'x'; MAX_STDERR_BYTES as usize]).unwrap();
        drop(open_stderr_log(home.path()).expect("stderr log"));
        let rotated = home.path().join(LOG_DIRECTORY).join(ROTATED_STDERR_LOG);
        assert_eq!(fs::metadata(&rotated).unwrap().len(), MAX_STDERR_BYTES);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_widened_log_is_made_private_before_it_is_rotated() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join(LOG_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        let path = directory.join(STDERR_LOG);
        fs::write(&path, vec![b'x'; MAX_STDERR_BYTES as usize]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        drop(open_stderr_log(home.path()).expect("stderr log"));
        let rotated = directory.join(ROTATED_STDERR_LOG);
        assert_eq!(fs::metadata(&rotated).unwrap().len(), MAX_STDERR_BYTES);
        assert_eq!(
            fs::metadata(&rotated).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_missing_home_gets_no_log() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("absent");
        assert!(open_stderr_log(&missing).is_none());
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_directory_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), home.path().join(LOG_DIRECTORY)).unwrap();
        assert!(open_stderr_log(home.path()).is_none());
        assert!(!elsewhere.path().join(STDERR_LOG).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_the_log_does_not_hold_up_the_launch() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join(LOG_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        let path = directory.join(STDERR_LOG);
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let (sender, receiver) = std::sync::mpsc::channel();
        let home_path = home.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = sender.send(open_stderr_log(&home_path).is_none());
        });
        let refused = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("opening the stderr log waited on a FIFO");
        assert!(refused);
    }
}
