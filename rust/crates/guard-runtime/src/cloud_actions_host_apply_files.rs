//! File steps behind the Cloud actions settings write: the bounded read, the
//! temporary file, the move into place and the checks around it.
//!
//! Every step that a test needs to make fail or race goes through `Ops`, so a
//! test can change the file at the exact moment Guard is about to move its own
//! file into place, or make the move itself fail.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use sha2::{Digest, Sha256};

pub(super) const MAX_SETTINGS_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const NEW_FILE_MODE: u32 = 0o600;
pub(super) const PRIVATE_DIR_MODE: u32 = 0o700;
const REPLACE_ATTEMPTS: u32 = 20;
const REPLACE_RETRY: Duration = Duration::from_millis(25);
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SHARING_VIOLATION: i32 = 32;

/// The settings file was not changed; `reason` says why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WriteError {
    pub(super) reason: &'static str,
    pub(super) message: String,
}

impl WriteError {
    pub(super) fn new(reason: &'static str, message: String) -> Self {
        Self { reason, message }
    }
}

/// Why a step did not finish. `Interrupt` stands for the process being
/// stopped part-way, which only a test can make happen.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(super) enum Failure {
    Write(WriteError),
    Io(io::Error),
    Interrupt,
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WriteError> for Failure {
    fn from(error: WriteError) -> Self {
        Self::Write(error)
    }
}

pub(super) trait Ops {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, Failure> {
        read_checked(path).map_err(Failure::from)
    }

    fn write_temporary(&self, path: &Path, payload: &[u8], mode: u32) -> Result<PathBuf, Failure> {
        write_temporary(path, payload, mode).map_err(Failure::from)
    }

    fn replace(&self, from: &Path, to: &Path) -> Result<(), Failure> {
        replace_file(from, to).map_err(Failure::from)
    }

    fn link(&self, from: &Path, to: &Path) -> Result<(), Failure> {
        fs::hard_link(from, to).map_err(Failure::from)
    }

    fn moved(&self, temporary: &Path, path: &Path, create: bool) -> Option<bool> {
        moved(temporary, path, create)
    }
}

pub(super) struct Real;

impl Ops for Real {}

/// The OS message alone, as `OSError.strerror` reads it; `error` when the
/// failure carries no OS message.
pub(super) fn strerror(error: &io::Error) -> String {
    if error.raw_os_error().is_none() {
        return "error".to_owned();
    }
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(index) if text.ends_with(')') => text[..index].to_owned(),
        _ => text,
    }
}

pub(super) fn sha256_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

/// `os.path.abspath` for a path that is already absolute: `.` and `..` are
/// collapsed in the text, links are not followed.
pub(super) fn absolute(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn unreadable(path: &Path, error: &io::Error) -> String {
    format!(
        "{} could not be read ({}).",
        path.display(),
        strerror(error)
    )
}

/// The file's bytes, or `None` when it does not exist; the message says why
/// it cannot be read safely. A named pipe or device is refused rather than read.
pub(super) fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if absent(&error) => return Ok(None),
        Err(error) => return Err(unreadable(path, &error)),
    };
    if !metadata.is_file() {
        return Err(format!("{} is not a file.", path.display()));
    }
    let too_large = || format!("{} is too large to change safely.", path.display());
    if metadata.len() > MAX_SETTINGS_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_SETTINGS_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| unreadable(path, &error))?;
    if bytes.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(too_large());
    }
    Ok(Some(bytes))
}

pub(super) fn read_checked(path: &Path) -> Result<Option<Vec<u8>>, WriteError> {
    read_bounded(path).map_err(|message| WriteError::new("unreadable", message))
}

pub(super) fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

pub(super) fn refuse_link(path: &Path) -> Result<(), WriteError> {
    if is_link(path) {
        return Err(WriteError::new(
            "settings_file_is_link",
            format!(
                "{} is a link. Guard changes only a regular file; add the entry to the file it points to yourself.",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn changed_since_preview(path: &Path) -> WriteError {
    WriteError::new(
        "changed_since_preview",
        format!(
            "{} changed after Guard read it, so nothing was written. Run the command again.",
            path.display()
        ),
    )
}

#[cfg(unix)]
pub(super) fn file_mode(path: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
pub(super) fn file_mode(path: &Path) -> io::Result<u32> {
    let readonly = fs::metadata(path)?.permissions().readonly();
    Ok(if readonly { 0o444 } else { 0o666 })
}

#[cfg(unix)]
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    file.set_permissions(permissions)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> io::Result<bool> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Whether Guard's temporary file is now the file at `path`; `None` when that
/// cannot be told.
fn moved(temporary: &Path, path: &Path, create: bool) -> Option<bool> {
    let outcome = if create {
        // A hard link leaves the temporary file in place, sharing the new file's data.
        fs::metadata(temporary).and_then(|left| {
            let right = fs::metadata(path)?;
            same_file(&left, &right)
        })
    } else {
        fs::symlink_metadata(temporary).map(|_| false)
    };
    match outcome {
        Ok(same) => Some(same),
        // Created: nothing at `path` yet. Replaced: the temporary file was moved away.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Some(!create),
        Err(_) => None,
    }
}

/// A new file beside `path`, holding `payload` and synced, with `mode`.
fn write_temporary(path: &Path, payload: &[u8], mode: u32) -> io::Result<PathBuf> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut file = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".guard-tmp")
        .tempfile_in(directory)?;
    set_mode(file.as_file(), mode)?;
    file.write_all(payload)?;
    file.flush()?;
    file.as_file().sync_all()?;
    let (_, temporary) = file.into_parts();
    temporary.keep().map_err(|error| error.error)
}

/// Move `from` over `to` in one step; Windows refuses while a reader holds the
/// destination open, so that is retried for half a second.
pub(super) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 1;
    loop {
        match fs::rename(from, to) {
            Err(error)
                if cfg!(windows)
                    && attempt < REPLACE_ATTEMPTS
                    && matches!(
                        error.raw_os_error(),
                        Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
                    ) =>
            {
                attempt += 1;
                sleep(REPLACE_RETRY);
            }
            outcome => return outcome,
        }
    }
}

/// Make a rename durable where the platform can; a filesystem that cannot
/// sync a directory is not a failed write.
pub(super) fn sync_directory(directory: &Path) {
    if cfg!(windows) {
        return;
    }
    let _ = File::open(directory).and_then(|handle| handle.sync_all());
}

pub(super) fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Owner-only access: the folder holds copies of AI tool settings files.
pub(super) fn private_dir(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)?;
    if cfg!(windows) {
        return Ok(());
    }
    set_directory_mode(directory, PRIVATE_DIR_MODE)
}

#[cfg(unix)]
fn set_directory_mode(directory: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(directory, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_directory_mode(_directory: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}
