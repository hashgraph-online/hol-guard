//! Shared, side-effect-free helpers for contained local runners.
//!
//! Faithful port of `runtime/contained_execution_common.py` plus the path
//! canonicalisation and framed-digest helpers of `runtime/containment_contract.py`.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const ALLOWED_ENVIRONMENT_KEYS: [&str; 5] = ["LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM"];

pub(crate) use crate::launch_identity_common::sha256_hex;

/// `_path_digest` / `_value_digest`: plain SHA-256 of the UTF-8 text.
pub(crate) fn text_digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

/// `json.dumps(sort_keys, separators=(",", ":"), ensure_ascii=True)`.
pub(crate) fn canonical_bytes(payload: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    guard_contracts::write_canonical_json(payload, &mut out).map_err(str::to_owned)?;
    Ok(out)
}

/// `_framed_digest` / `containment_binding_digest`: SHA-256 over an 8-byte
/// big-endian length followed by the canonical payload.
pub(crate) fn framed_digest(payload: &Value) -> Result<String, String> {
    let encoded = canonical_bytes(payload)?;
    let mut framed = (encoded.len() as u64).to_be_bytes().to_vec();
    framed.extend_from_slice(&encoded);
    Ok(sha256_hex(&framed))
}

/// `os.path.normpath` for POSIX paths.
pub(crate) fn normpath(value: &str) -> String {
    if value.is_empty() {
        return ".".to_owned();
    }
    let initial = if value.starts_with("//") && !value.starts_with("///") {
        2
    } else if value.starts_with('/') {
        1
    } else {
        0
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part != ".."
            || (initial == 0 && parts.is_empty())
            || parts.last().is_some_and(|last| *last == "..")
        {
            parts.push(part);
        } else if !parts.is_empty() {
            parts.pop();
        }
    }
    let joined = format!("{}{}", "/".repeat(initial), parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

fn access_executable(path: &Path) -> bool {
    nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

fn canonical_checked(path: &Path, value: &str, alias_message: &str) -> Result<String, String> {
    let canonical = fs::canonicalize(path).map_err(|_| alias_message.to_owned())?;
    let canonical = canonical.to_string_lossy().into_owned();
    if canonical != normpath(value) {
        return Err(alias_message.to_owned());
    }
    Ok(canonical)
}

fn non_empty_path(value: &str, name: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\0') {
        return Err(format!("{name} must be a non-empty path"));
    }
    Ok(())
}

/// `_canonical_directory`.
pub(crate) fn canonical_directory(value: &str, name: &str) -> Result<String, String> {
    non_empty_path(value, name)?;
    let path = Path::new(value);
    if !path.is_absolute() || is_symlink(path) || !path.is_dir() {
        return Err(format!("{name} must be an existing canonical directory"));
    }
    canonical_checked(
        path,
        value,
        &format!("{name} must not contain symlink or traversal aliases"),
    )
}

/// `_canonical_file`.
pub(crate) fn canonical_file(value: &str, name: &str) -> Result<String, String> {
    non_empty_path(value, name)?;
    let path = Path::new(value);
    if !path.is_absolute() || is_symlink(path) || !path.is_file() {
        return Err(format!("{name} must be an existing canonical file"));
    }
    canonical_checked(
        path,
        value,
        &format!("{name} must not contain symlink or traversal aliases"),
    )
}

/// `_canonical_executable`.
pub(crate) fn canonical_executable(value: &str) -> Result<String, String> {
    non_empty_path(value, "executable")?;
    let path = Path::new(value);
    if !path.is_absolute() || is_symlink(path) || !path.is_file() || !access_executable(path) {
        return Err("executable must be an existing path-pinned executable".to_owned());
    }
    canonical_checked(
        path,
        value,
        "executable must not contain symlink or traversal aliases",
    )
}

/// `canonical_existing_directory` (workspace flavour).
pub(crate) fn canonical_workspace(path: &Path) -> Result<PathBuf, String> {
    if is_symlink(path) || !path.is_dir() {
        return Err("workspace must be an existing canonical directory".to_owned());
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| "workspace cannot contain aliases".to_owned())?;
    if canonical.to_string_lossy() != normpath(&path.to_string_lossy()) {
        return Err("workspace cannot contain aliases".to_owned());
    }
    Ok(canonical)
}

/// `open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW)`.
pub(crate) fn open_nofollow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

type ContentIdentity = (u64, u64, u64, i64, i64, u32);

/// `content_stat_identity`.
pub(crate) fn content_identity(metadata: &fs::Metadata) -> ContentIdentity {
    let mtime_ns = metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec();
    let ctime_ns = metadata.ctime() * 1_000_000_000 + metadata.ctime_nsec();
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        mtime_ns,
        ctime_ns,
        metadata.mode(),
    )
}

/// `file_sha256`: hash one bounded, non-symlinked regular file and prove its
/// identity did not change while hashing.
pub(crate) fn file_sha256(path: &Path) -> Result<String, String> {
    let mut file = open_nofollow(path).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            "executable must not be a symlink".to_owned()
        } else {
            error.to_string()
        }
    })?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || before.size() > MAX_EXECUTABLE_BYTES {
        return Err("executable must be a bounded regular file".to_owned());
    }
    let before_identity = content_identity(&before);
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut read_bytes: u64 = 0;
    loop {
        let count = loop {
            match file.read(&mut buffer) {
                Ok(count) => break count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            }
        };
        if count == 0 {
            break;
        }
        read_bytes += count as u64;
        if read_bytes > MAX_EXECUTABLE_BYTES {
            return Err("executable must be a bounded regular file".to_owned());
        }
        digest.update(&buffer[..count]);
    }
    if read_bytes != before.size() {
        return Err("executable identity changed while hashing".to_owned());
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    let after_identity = content_identity(&after);
    if after_identity != before_identity {
        return Err("executable identity changed while hashing".to_owned());
    }
    let final_path = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !final_path.is_file() || content_identity(&final_path) != after_identity {
        return Err("executable identity changed while hashing".to_owned());
    }
    Ok(hex::encode(digest.finalize()))
}

/// `clean_containment_environment`: only non-sensitive presentation variables.
pub(crate) fn clean_environment(environment: &BTreeMap<String, String>) -> Vec<(String, String)> {
    ALLOWED_ENVIRONMENT_KEYS
        .iter()
        .filter_map(|key| {
            environment
                .get(*key)
                .filter(|value| !value.is_empty())
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect()
}
