//! The native daemon's standard error, kept in a private file under the
//! Guard home instead of the null device, so the message a daemon prints as
//! it fails (a listener error, a state it could not publish) is still there
//! when someone looks for why it stopped.
//!
//! The file is opened by the launcher and handed to the daemon. It is rotated
//! at launch once it reaches `MAX_STDERR_BYTES`, keeping one previous file.
//! Any problem opening it falls back to the null device: a daemon must never
//! fail to start for want of a log.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;
use std::process::Stdio;

const LOG_DIRECTORY: &str = "logs";
const STDERR_LOG: &str = "daemon-serve.stderr";
const ROTATED_STDERR_LOG: &str = "daemon-serve.stderr.1";
const MAX_STDERR_BYTES: u64 = 1024 * 1024;

/// Standard error for a native daemon of `home`.
pub(super) fn daemon_stderr(home: &Path) -> Stdio {
    open_stderr_log(home).map_or_else(Stdio::null, Stdio::from)
}

fn open_stderr_log(home: &Path) -> Option<File> {
    if !home.is_dir() || is_symlink(home) {
        return None;
    }
    let directory = home.join(LOG_DIRECTORY);
    if is_symlink(&directory) {
        return None;
    }
    if !directory.exists() {
        create_private_directory(&directory)?;
    }
    if !directory.is_dir() {
        return None;
    }
    let path = directory.join(STDERR_LOG);
    if is_symlink(&path) {
        return None;
    }
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_STDERR_BYTES) {
        let rotated = directory.join(ROTATED_STDERR_LOG);
        if is_symlink(&rotated) {
            return None;
        }
        fs::rename(&path, &rotated).ok()?;
    }
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(&path).ok()
}

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> Option<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(directory) {
        Ok(()) => Some(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Some(()),
        Err(_) => None,
    }
}

#[cfg(not(unix))]
fn create_private_directory(directory: &Path) -> Option<()> {
    match fs::create_dir(directory) {
        Ok(()) => Some(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Some(()),
        Err(_) => None,
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
