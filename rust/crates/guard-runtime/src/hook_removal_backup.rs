//! The backups `hol-guard hooks remove` takes before it edits a harness
//! config file (`op: "backup"`), and the pass that keeps only the copies of
//! files that changed (`op: "finalize-backups"`).
//!
//! A harness whose files cannot all be copied is never edited, so `backup`
//! answers `{"outcome": "error"}` and removes the copies it wrote for that
//! harness. Every copy is created owner-only with `create_new`, inside an
//! owner-only directory that must not be a symlink.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{absolute, invalid, Request};

const MAX_BACKUP_FILES: usize = 64;
const MAX_FINALIZE_ENTRIES: usize = 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ERROR_CHARS: usize = 160;
const MANIFEST_NAME: &str = "manifest.json";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackupEntry {
    harness: String,
    original_path: String,
    backup_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

/// Copy each existing file in `candidates` that `skip` does not name.
pub(super) fn backup(request: &Request) -> Result<Value, String> {
    let directory = backup_directory(request)?;
    let harness = request.harness.as_deref().ok_or_else(invalid)?;
    if !valid_harness(harness)
        || request.candidates.len() > MAX_BACKUP_FILES
        || !request.entries.is_empty()
        || request.stamp.is_some()
    {
        return Err(invalid());
    }
    // Every path is checked before the first copy, so a refused request
    // leaves nothing behind.
    let candidates = request
        .candidates
        .iter()
        .map(|text| Ok((text.as_str(), absolute(text)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let mut seen: BTreeSet<&str> = request.skip.iter().map(String::as_str).collect();
    let mut entries: Vec<BackupEntry> = Vec::new();
    for (text, path) in candidates {
        // A file named twice, or already copied for an earlier harness,
        // keeps its first (pre-edit) copy.
        if !seen.insert(text) {
            continue;
        }
        match copy_one(&directory, harness, text, &path) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(error) => {
                for entry in &entries {
                    let _ = fs::remove_file(&entry.backup_path);
                }
                return Ok(json!({ "outcome": "error", "error": error_text(&error) }));
            }
        }
    }
    Ok(json!({ "outcome": "ok", "entries": entries }))
}

/// Drop the copies of files that still hash as they did, and write the
/// manifest for the rest. An empty backup directory is removed.
pub(super) fn finalize(request: &Request) -> Result<Value, String> {
    let directory = absolute(request.backup_dir.as_deref().ok_or_else(invalid)?)?;
    let stamp = request.stamp.as_deref().ok_or_else(invalid)?;
    if request.harness.is_some()
        || !request.candidates.is_empty()
        || !request.skip.is_empty()
        || request.entries.len() > MAX_FINALIZE_ENTRIES
    {
        return Err(invalid());
    }
    // Every entry is checked before the first removal, so a refused request
    // never costs a copy.
    let mut checked: Vec<(&BackupEntry, PathBuf, PathBuf)> = Vec::new();
    for entry in &request.entries {
        let original = absolute(&entry.original_path)?;
        let copy = absolute(&entry.backup_path)?;
        // Only a copy this pass wrote, directly inside the backup directory,
        // is ever removed.
        if copy.parent() != Some(directory.as_path()) || entry.sha256.is_none() {
            return Err(invalid());
        }
        checked.push((entry, original, copy));
    }
    let mut kept: Vec<BackupEntry> = Vec::new();
    for (entry, original, copy) in checked {
        if current_digest(&original).as_deref() == entry.sha256.as_deref() {
            let _ = fs::remove_file(&copy);
            continue;
        }
        kept.push(BackupEntry {
            sha256: None,
            ..entry.clone()
        });
    }
    if kept.is_empty() {
        let _ = fs::remove_dir(&directory);
        return Ok(json!({ "backup_dir": null, "files": [] }));
    }
    // The copies are already in place; a manifest that cannot be written
    // costs only the summary, as before.
    let _ = write_manifest(&directory, stamp, &kept);
    Ok(json!({ "backup_dir": request.backup_dir, "files": kept }))
}

fn backup_directory(request: &Request) -> Result<PathBuf, String> {
    absolute(request.backup_dir.as_deref().ok_or_else(invalid)?)
}

/// A harness name is spliced into a file name, so it may not carry a path
/// separator or start with a dot.
fn valid_harness(harness: &str) -> bool {
    !harness.is_empty()
        && harness.len() <= 64
        && !harness.starts_with('.')
        && harness
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn copy_one(
    directory: &Path,
    harness: &str,
    text: &str,
    path: &Path,
) -> io::Result<Option<BackupEntry>> {
    let original = match read_bounded(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    private_directory(directory)?;
    let name = path
        .file_name()
        .ok_or(io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let tag = &hex::encode(Sha256::digest(text.as_bytes()))[..8];
    let target = directory.join(format!("{harness}-{tag}-{name}"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&target)?;
    let written = file.write_all(&original).and_then(|()| file.sync_all());
    if let Err(error) = written {
        drop(file);
        let _ = fs::remove_file(&target);
        return Err(error);
    }
    Ok(Some(BackupEntry {
        harness: harness.to_owned(),
        original_path: text.to_owned(),
        backup_path: target.to_string_lossy().into_owned(),
        sha256: Some(hex::encode(Sha256::digest(&original))),
    }))
}

/// The config file as the harness reads it, through any symlink.
fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config file too large to back up",
        ));
    }
    Ok(bytes)
}

/// Create the backup directory owner-only, refusing one that is a symlink or
/// not a directory.
fn private_directory(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup directory is not a directory",
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(
        directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    Ok(())
}

fn current_digest(path: &Path) -> Option<String> {
    read_bounded(path)
        .ok()
        .map(|bytes| hex::encode(Sha256::digest(&bytes)))
}

fn write_manifest(directory: &Path, stamp: &str, files: &[BackupEntry]) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(&json!({ "created_at": stamp, "files": files }))
        .map_err(io::Error::other)?;
    bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    let mut file = options.open(directory.join(MANIFEST_NAME))?;
    file.write_all(&bytes)?;
    file.sync_all()
}

fn error_text(error: &io::Error) -> String {
    let text = format!("backup_failed: {error}");
    text.chars().take(MAX_ERROR_CHARS).collect()
}

#[cfg(all(test, unix))]
#[path = "hook_removal_backup_tests.rs"]
mod tests;
