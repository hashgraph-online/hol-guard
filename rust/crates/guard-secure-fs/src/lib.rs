#![forbid(unsafe_code)]

use guard_rules::MAX_SCAN_BYTES;
use sha2::{Digest, Sha256};
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

mod secure_open;
mod source_path;

use secure_open::{secure_open, SecureOpenError};
pub use source_path::{classify_source_path, sensitive_path_family, source_like};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    pub size: u64,
    pub mtime_ns: u128,
    /// The permission/type bits are part of identity so a permission change
    /// during a read cannot be mistaken for an unchanged source file.
    pub mode: u32,
    /// A decision-critical source read must not follow a multiply-linked file:
    /// another pathname could mutate the bytes after the path was classified.
    pub nlink: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRead {
    pub bytes: Vec<u8>,
    pub identity: FileIdentity,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePathDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
    pub resolved_path: Option<PathBuf>,
}

impl SourcePathDecision {
    fn allow(reason_code: &'static str, path: PathBuf) -> Self {
        Self {
            allowed: true,
            reason_code,
            resolved_path: Some(path),
        }
    }

    fn deny(reason_code: &'static str) -> Self {
        Self {
            allowed: false,
            reason_code,
            resolved_path: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum SecureReadError {
    #[error("unresolved_path")]
    UnresolvedPath,
    #[error("symlink_in_path")]
    SymlinkInPath,
    #[error("not_regular_file")]
    NotRegularFile,
    #[error("hard_linked_file")]
    HardLinkedFile,
    #[error("permission_denied")]
    PermissionDenied,
    #[error("source_file_too_large")]
    TooLarge,
    #[error("read_failed")]
    ReadFailed,
    #[error("source_stat_changed")]
    Changed,
    #[error("source_path_changed")]
    PathChanged,
}

pub fn resolve_candidate(
    target: &str,
    cwd: Option<&Path>,
    home: &Path,
) -> Result<PathBuf, SecureReadError> {
    let stripped = target.trim().trim_matches(['\'', '"']);
    if stripped.is_empty() {
        return Err(SecureReadError::UnresolvedPath);
    }
    if stripped == "~" {
        return Ok(home.to_path_buf());
    }
    if let Some(rest) = stripped.strip_prefix("~/") {
        return Ok(home.join(rest));
    }
    if stripped.starts_with('~') {
        return Err(SecureReadError::UnresolvedPath);
    }
    let path = PathBuf::from(stripped);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(cwd.unwrap_or_else(|| Path::new(".")).join(path))
}

pub fn contains_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        let should_stat = match component {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
                false
            }
            Component::RootDir => {
                current.push(Path::new(std::path::MAIN_SEPARATOR_STR));
                false
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                current.push("..");
                false
            }
            Component::Normal(part) => {
                current.push(part);
                true
            }
        };
        if !should_stat {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return true,
        }
    }
    false
}

fn identity(metadata: &Metadata) -> FileIdentity {
    let mtime_ns = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_nanos());
    #[cfg(unix)]
    let (dev, ino) = (Some(metadata.dev()), Some(metadata.ino()));
    #[cfg(not(unix))]
    let (dev, ino) = (None, None);
    #[cfg(unix)]
    let (mode, nlink) = (metadata.mode(), metadata.nlink());
    #[cfg(not(unix))]
    let (mode, nlink) = (0, 0);
    FileIdentity {
        dev,
        ino,
        size: metadata.len(),
        mtime_ns,
        mode,
        nlink,
    }
}

fn map_secure_open_error(error: SecureOpenError) -> SecureReadError {
    match error {
        SecureOpenError::PathChanged => SecureReadError::PathChanged,
        #[cfg(unix)]
        SecureOpenError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            SecureReadError::PermissionDenied
        }
        #[cfg(unix)]
        SecureOpenError::Io(_) => SecureReadError::ReadFailed,
    }
}

pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<SecureRead, SecureReadError> {
    let max_bytes = max_bytes.min(MAX_SCAN_BYTES);
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    #[cfg(not(unix))]
    if secure_open::is_oversized_regular_file(path, max_bytes) {
        return Err(SecureReadError::TooLarge);
    }
    // Canonicalize around a descriptor-bound read to close path races.
    let canonical_before = fs::canonicalize(path).map_err(|_| SecureReadError::ReadFailed)?;
    let mut file = secure_open(path, &canonical_before).map_err(map_secure_open_error)?;
    let before_metadata = file.metadata().map_err(|_| SecureReadError::ReadFailed)?;
    if !before_metadata.is_file() {
        return Err(SecureReadError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        let mode = before_metadata.mode();
        if mode & 0o444 == 0 {
            return Err(SecureReadError::PermissionDenied);
        }
        if before_metadata.nlink() != 1 {
            return Err(SecureReadError::HardLinkedFile);
        }
    }
    if before_metadata.len() > max_bytes as u64 {
        return Err(SecureReadError::TooLarge);
    }
    let before = identity(&before_metadata);
    let mut bytes = Vec::with_capacity(before.size as usize);
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureReadError::ReadFailed)?;
    if bytes.len() > max_bytes {
        return Err(SecureReadError::TooLarge);
    }
    let after = identity(&file.metadata().map_err(|_| SecureReadError::ReadFailed)?);
    if before != after {
        return Err(SecureReadError::Changed);
    }
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    let canonical_after = fs::canonicalize(path).map_err(|_| SecureReadError::PathChanged)?;
    if canonical_before != canonical_after {
        return Err(SecureReadError::PathChanged);
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(SecureRead {
        bytes,
        identity: after,
        sha256: hex::encode(hasher.finalize()),
    })
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
