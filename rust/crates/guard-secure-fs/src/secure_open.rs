use std::fs::File;
#[cfg(unix)]
use std::fs::{self, Metadata};
use std::io;
use std::path::Path;
#[cfg(unix)]
use std::path::{Component, PathBuf};

#[cfg(unix)]
use nix::fcntl::{open, openat, OFlag};
#[cfg(unix)]
use nix::sys::stat::Mode;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Debug)]
pub(crate) enum SecureOpenError {
    Io(io::Error),
    PathChanged,
}

#[cfg(unix)]
pub(crate) fn secure_open(_path: &Path, canonical_path: &Path) -> Result<File, SecureOpenError> {
    let mut expected_components = Vec::new();
    let mut prefix = PathBuf::from("/");
    for component in canonical_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                prefix.push(part);
                let metadata = fs::symlink_metadata(&prefix).map_err(SecureOpenError::Io)?;
                expected_components.push((part.to_os_string(), metadata));
            }
            _ => return Err(SecureOpenError::PathChanged),
        }
    }
    if expected_components.is_empty() {
        return Err(SecureOpenError::PathChanged);
    }

    let root = open(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| SecureOpenError::Io(io::Error::from_raw_os_error(error as i32)))?;
    let mut parent = File::from(root);
    for (index, (name, expected)) in expected_components.iter().enumerate() {
        if expected.file_type().is_symlink() {
            return Err(SecureOpenError::PathChanged);
        }
        let final_component = index + 1 == expected_components.len();
        let flags = if final_component {
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
        } else {
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
        };
        let descriptor = openat(&parent, name.as_os_str(), flags, Mode::empty())
            .map_err(|error| SecureOpenError::Io(io::Error::from_raw_os_error(error as i32)))?;
        let opened = File::from(descriptor);
        let actual = opened.metadata().map_err(SecureOpenError::Io)?;
        let identity_matches = if final_component {
            same_unix_identity(expected, &actual)
        } else {
            same_unix_directory_identity(expected, &actual)
        };
        if !identity_matches {
            return Err(SecureOpenError::PathChanged);
        }
        if final_component {
            return Ok(opened);
        }
        parent = opened;
    }
    Err(SecureOpenError::PathChanged)
}

#[cfg(unix)]
fn same_unix_identity(expected: &Metadata, actual: &Metadata) -> bool {
    expected.dev() == actual.dev()
        && expected.ino() == actual.ino()
        && expected.mode() == actual.mode()
        && expected.nlink() == actual.nlink()
}

#[cfg(unix)]
fn same_unix_directory_identity(expected: &Metadata, actual: &Metadata) -> bool {
    expected.dev() == actual.dev()
        && expected.ino() == actual.ino()
        && expected.mode() == actual.mode()
}

#[cfg(not(unix))]
pub(crate) fn secure_open(_path: &Path, _canonical_path: &Path) -> Result<File, SecureOpenError> {
    // Opening the caller-provided path directly would reintroduce a TOCTOU
    // window. Keep non-Unix platforms fail-closed until they have an
    // equivalent descriptor/handle-bound path walk.
    Err(SecureOpenError::PathChanged)
}
