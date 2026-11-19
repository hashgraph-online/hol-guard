//! A durable copy of a frozen Guard's native runtime for installed hook and
//! MCP relay commands (`native_runtime_durable.py` before it moved).
//!
//! A frozen Guard carries the native runtime as bundled data. A onefile build
//! extracts it under a per-launch `_MEI*` directory that disappears when the
//! process exits, and a Desktop app bundle can move between updates, so
//! neither path can be written into a harness command. The command instead
//! names a content-addressed copy under the Guard home, which is always
//! user-writable: `<guard_home>/native-runtime/<sha256>/<runtime name>`.
//!
//! The copy is published only from bytes that hash to the validated runtime
//! identity, and is reused only while it is a regular, owner-owned,
//! owner-executable file with the same size and digest and no group or world
//! write bit. Anything else yields `None`, so the caller keeps its fail-closed
//! launcher. A copy whose digest was verified is not hashed again in the same
//! process until its file metadata changes.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

/// The directory under the Guard home that holds the copies.
const DIRECTORY: &str = "native-runtime";
const CHUNK_BYTES: usize = 1024 * 1024;

/// The validated native runtime a copy is made from.
pub(super) struct Identity<'a> {
    pub(super) path: &'a Path,
    pub(super) size: u64,
    pub(super) sha256: &'a str,
}

/// The file metadata a verified copy had when its digest matched.
type Witness = (String, u64, Vec<i64>);

fn verified() -> &'static Mutex<HashMap<PathBuf, Witness>> {
    static VERIFIED: OnceLock<Mutex<HashMap<PathBuf, Witness>>> = OnceLock::new();
    VERIFIED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Where the copy of `identity` lives under `guard_home`.
fn copy_path(identity: &Identity<'_>, guard_home: &Path) -> Option<PathBuf> {
    let name = identity.path.file_name()?;
    Some(guard_home.join(DIRECTORY).join(identity.sha256).join(name))
}

/// The verified durable copy of `identity`, publishing it when absent.
pub(super) fn hook_runtime(identity: &Identity<'_>, guard_home: &Path) -> Option<PathBuf> {
    if !is_digest(identity.sha256) {
        return None;
    }
    let target = copy_path(identity, guard_home)?;
    if trusted(&target, identity) {
        return Some(target);
    }
    let parent = target.parent()?;
    let published = private_directory(guard_home)
        .and_then(|()| private_directory(parent.parent().unwrap_or(parent)))
        .and_then(|()| private_directory(parent))
        .and_then(|()| publish(identity, &target, parent));
    match published {
        Ok(()) if trusted(&target, identity) => Some(target),
        _ => None,
    }
}

fn trusted(path: &Path, identity: &Identity<'_>) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.len() != identity.size {
        return false;
    }
    if !owner_executable(&metadata) {
        return false;
    }
    let witness = (
        identity.sha256.to_owned(),
        metadata.len(),
        stamps(&metadata),
    );
    if let Ok(known) = verified().lock() {
        if known.get(path) == Some(&witness) {
            return true;
        }
    }
    let matches = file_sha256(path).is_ok_and(|digest| digest == identity.sha256);
    if matches {
        if let Ok(mut known) = verified().lock() {
            known.insert(path.to_path_buf(), witness);
        }
    }
    matches
}

#[cfg(unix)]
fn owner_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o7777;
    metadata.uid() == nix::unistd::getuid().as_raw() && mode & 0o022 == 0 && mode & 0o100 != 0
}

#[cfg(windows)]
fn owner_executable(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn stamps(metadata: &fs::Metadata) -> Vec<i64> {
    use std::os::unix::fs::MetadataExt;
    let nanos =
        |seconds: i64, nanos: i64| seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
    vec![
        nanos(metadata.mtime(), metadata.mtime_nsec()),
        nanos(metadata.ctime(), metadata.ctime_nsec()),
        i64::try_from(metadata.ino()).unwrap_or(-1),
        i64::try_from(metadata.dev()).unwrap_or(-1),
    ]
}

#[cfg(windows)]
fn stamps(metadata: &fs::Metadata) -> Vec<i64> {
    use std::os::windows::fs::MetadataExt;
    vec![
        i64::try_from(metadata.last_write_time()).unwrap_or(-1),
        i64::try_from(metadata.creation_time()).unwrap_or(-1),
    ]
}

/// `_ensure_private_directory`: create it owner-only, refuse a link, a
/// non-directory or another owner, and drop group and world write.
fn private_directory(path: &Path) -> io::Result<()> {
    create_private(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "durable native runtime directory is not a regular directory: {}",
            path.display()
        )));
    }
    restrict_directory(path, &metadata)
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(windows)]
fn create_private(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).create(path)
}

#[cfg(unix)]
fn restrict_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        return Err(io::Error::other(format!(
            "durable native runtime directory has an unexpected owner: {}",
            path.display()
        )));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o022))?;
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_directory(_path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

/// Copy the runtime through a temporary file beside `target`, checking that
/// the bytes copied hash to the identity, then replace the target.
fn publish(identity: &Identity<'_>, target: &Path, parent: &Path) -> io::Result<()> {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(parent)?;
    let mut source = File::open(identity.path)?;
    let mut digest = Sha256::new();
    let mut size: u64 = 0;
    let mut chunk = vec![0u8; CHUNK_BYTES];
    loop {
        let read = source.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        digest.update(&chunk[..read]);
        size += read as u64;
        temporary.write_all(&chunk[..read])?;
    }
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    if size != identity.size || hex::encode(digest.finalize()) != identity.sha256 {
        return Err(io::Error::other(
            "bundled native runtime changed while it was copied",
        ));
    }
    owner_only_executable(temporary.path())?;
    temporary.persist(target).map_err(|error| error.error)?;
    sync_directory(parent)
}

#[cfg(unix)]
fn owner_only_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn owner_only_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut chunk = vec![0u8; CHUNK_BYTES];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(hex::encode(digest.finalize()));
        }
        digest.update(&chunk[..read]);
    }
}
