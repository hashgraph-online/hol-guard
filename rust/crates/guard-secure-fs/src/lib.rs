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
pub use source_path::{
    classify_scannable_source_path, classify_source_path, credential_named_path,
    credential_path_markers, hidden_read_parts_allowed, is_source_code_extension,
    sensitive_external_filename, sensitive_path_family, source_like, EXTERNAL_SENSITIVE_PARTS,
};

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

/// An open read-only descriptor bound to a verified immutable leaf file.
///
/// The descriptor was opened through the canonical component walk in
/// `secure_open`, so the bytes read from it are the bytes whose identity was
/// admitted: a regular file with exactly one link and no write permission
/// bits. Ancestor symlinks in the caller-supplied path are resolved before
/// the walk; a symlink leaf is rejected before open.
#[derive(Debug)]
pub struct SecureBlob {
    pub file: std::fs::File,
    pub identity: FileIdentity,
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
    /// The leaf file still has owner/group/other write bits set: callers that
    /// require an immutable artifact reject it before any bytes are read.
    #[error("mutable_leaf")]
    MutableLeaf,
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

/// Identity of the regular file at `path`, which must have exactly one
/// directory entry.
#[cfg(windows)]
fn windows_file_id(
    path: &Path,
    follow_leaf: bool,
) -> Result<guard_runtime_windows_process::FileId, SecureReadError> {
    let (id, links) = guard_runtime_windows_process::regular_file_id(path, follow_leaf)
        .map_err(|_| SecureReadError::ReadFailed)?;
    if links != 1 {
        return Err(SecureReadError::HardLinkedFile);
    }
    Ok(id)
}

/// Reject a handle that reached a different file from the one inspected.
#[cfg(windows)]
fn ensure_windows_handle_is(
    file: &fs::File,
    expected: guard_runtime_windows_process::FileId,
) -> Result<(), SecureReadError> {
    let opened = guard_runtime_windows_process::handle_file_id(file)
        .map_err(|_| SecureReadError::ReadFailed)?;
    if opened != expected {
        return Err(SecureReadError::Changed);
    }
    Ok(())
}

fn map_secure_open_error(error: SecureOpenError) -> SecureReadError {
    match error {
        SecureOpenError::PathChanged => SecureReadError::PathChanged,
        #[cfg(any(unix, windows))]
        SecureOpenError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            SecureReadError::PermissionDenied
        }
        #[cfg(any(unix, windows))]
        SecureOpenError::Io(_) => SecureReadError::ReadFailed,
    }
}

/// Open a caller-supplied path as a digest-bound immutable blob.
///
/// Equivalent admission rules to `read_bounded` for the leaf — regular file,
/// single link, no write bits, identity revalidated against the opened
/// descriptor — but returns the descriptor so callers can stream and rehash
/// without holding the whole blob in memory. Ancestor components may be
/// symlinks; they are resolved by canonicalization before the descriptor
/// walk, matching the behavior of `resolve(strict=True)` callers.
pub fn open_immutable_blob(path: &Path) -> Result<SecureBlob, SecureReadError> {
    let leaf = fs::symlink_metadata(path).map_err(|_| SecureReadError::ReadFailed)?;
    if leaf.file_type().is_symlink() {
        return Err(SecureReadError::SymlinkInPath);
    }
    if !leaf.is_file() {
        return Err(SecureReadError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        if leaf.nlink() != 1 {
            return Err(SecureReadError::HardLinkedFile);
        }
        if leaf.mode() & 0o222 != 0 {
            return Err(SecureReadError::MutableLeaf);
        }
    }
    #[cfg(windows)]
    let leaf_id = windows_file_id(path, false)?;
    let canonical = fs::canonicalize(path).map_err(|_| SecureReadError::ReadFailed)?;
    let file = secure_open(path, &canonical).map_err(map_secure_open_error)?;
    #[cfg(windows)]
    ensure_windows_handle_is(&file, leaf_id)?;
    let live = file.metadata().map_err(|_| SecureReadError::ReadFailed)?;
    if !live.is_file() {
        return Err(SecureReadError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        if live.dev() != leaf.dev()
            || live.ino() != leaf.ino()
            || live.nlink() != 1
            || live.mode() & 0o222 != 0
        {
            return Err(SecureReadError::Changed);
        }
    }
    #[cfg(not(unix))]
    {
        if live.len() != leaf.len()
            || live
                .modified()
                .ok()
                .zip(leaf.modified().ok())
                .is_none_or(|(a, b)| a != b)
        {
            return Err(SecureReadError::Changed);
        }
    }
    Ok(SecureBlob {
        file,
        identity: identity(&live),
    })
}

/// Read a mutable context input without trusting a path-only snapshot.
///
/// Ancestor symlinks are resolved before the descriptor walk. Leaf symlinks
/// are admitted only for executable acquisition; callers set their own byte
/// limit rather than inheriting the source-scanner limit.
pub fn read_stable(
    path: &Path,
    max_bytes: usize,
    allow_leaf_symlink: bool,
) -> Result<SecureRead, SecureReadError> {
    fn checked_metadata(
        path: &Path,
        allow_leaf_symlink: bool,
    ) -> Result<Metadata, SecureReadError> {
        let leaf = fs::symlink_metadata(path).map_err(|_| SecureReadError::ReadFailed)?;
        if leaf.file_type().is_symlink() && !allow_leaf_symlink {
            return Err(SecureReadError::SymlinkInPath);
        }
        let metadata = fs::metadata(path).map_err(|_| SecureReadError::ReadFailed)?;
        if !metadata.is_file() {
            return Err(SecureReadError::NotRegularFile);
        }
        #[cfg(unix)]
        if metadata.mode() & 0o444 == 0 {
            return Err(SecureReadError::PermissionDenied);
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return Err(SecureReadError::HardLinkedFile);
        }
        Ok(metadata)
    }

    fn unchanged(before: &Metadata, after: &Metadata) -> bool {
        if identity(before) != identity(after) {
            return false;
        }
        #[cfg(unix)]
        {
            before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    let source_before = checked_metadata(path, allow_leaf_symlink)?;
    #[cfg(windows)]
    let source_id = windows_file_id(path, allow_leaf_symlink)?;
    if source_before.len() > max_bytes as u64 {
        return Err(SecureReadError::TooLarge);
    }
    let canonical_before = fs::canonicalize(path).map_err(|_| SecureReadError::ReadFailed)?;
    let mut file = secure_open(path, &canonical_before).map_err(map_secure_open_error)?;
    #[cfg(windows)]
    ensure_windows_handle_is(&file, source_id)?;
    let descriptor_before = file.metadata().map_err(|_| SecureReadError::ReadFailed)?;
    if !unchanged(&source_before, &descriptor_before) {
        return Err(SecureReadError::Changed);
    }
    let limit = (max_bytes as u64).saturating_add(1);
    let mut bytes = Vec::with_capacity(source_before.len() as usize);
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureReadError::ReadFailed)?;
    if bytes.len() > max_bytes {
        return Err(SecureReadError::TooLarge);
    }
    let descriptor_after = file.metadata().map_err(|_| SecureReadError::ReadFailed)?;
    let source_after = checked_metadata(path, allow_leaf_symlink)?;
    #[cfg(windows)]
    if windows_file_id(path, allow_leaf_symlink)? != source_id {
        return Err(SecureReadError::Changed);
    }
    if bytes.len() as u64 != source_before.len()
        || !unchanged(&descriptor_before, &descriptor_after)
        || !unchanged(&source_before, &source_after)
    {
        return Err(SecureReadError::Changed);
    }
    let canonical_after = fs::canonicalize(path).map_err(|_| SecureReadError::PathChanged)?;
    if canonical_before != canonical_after {
        return Err(SecureReadError::PathChanged);
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(SecureRead {
        bytes,
        identity: identity(&descriptor_after),
        sha256,
    })
}

pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<SecureRead, SecureReadError> {
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    let read = read_stable(path, max_bytes.min(MAX_SCAN_BYTES), false)?;
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    Ok(read)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
