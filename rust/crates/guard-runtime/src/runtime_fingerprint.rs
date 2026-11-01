//! `runtime-fingerprint --stdin`: the identity of an installed Guard source
//! tree, for daemon compatibility (`guard/daemon/manager.py` keeps the cache
//! file and memoises the answer).
//!
//! Two processes of the same install must compute the same identity, and an
//! in-place upgrade must change it. The identity covers every `*.py` file
//! under `codex_plugin_scanner`, the bundled native runtime manifest and the
//! daemon's static assets, read in sorted path order:
//!
//! - the tree signature hashes each file's relative path, size and
//!   modification time, which is cheap to recompute on every start;
//! - the content fingerprint hashes each file's relative path, size and
//!   bytes, and is what processes compare.
//!
//! A cached fingerprint whose tree signature still matches is returned
//! without reading any file, so only a changed tree pays for the content
//! hash.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "runtime-fingerprint.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const PACKAGE: &str = "codex_plugin_scanner";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    source_root: String,
    version: String,
    #[serde(default)]
    cached: Option<Cached>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    tree_sig: String,
    fingerprint: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "runtime-fingerprint"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "runtime_fingerprint_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("runtime_fingerprint_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let source_root = PathBuf::from(&request.source_root);
    if request.schema != SCHEMA || !source_root.is_absolute() {
        return Err(invalid());
    }
    Ok(
        answer(&source_root, &request.version, request.cached.as_ref())
            .to_string()
            .into_bytes(),
    )
}

fn invalid() -> String {
    "runtime_fingerprint_request_invalid".to_owned()
}

fn answer(source_root: &Path, version: &str, cached: Option<&Cached>) -> Value {
    let paths = identity_paths(source_root);
    let tree_sig = tree_signature(source_root, version, &paths);
    let reused =
        cached.filter(|cached| cached.tree_sig == tree_sig && is_sha256_hex(&cached.fingerprint));
    let (fingerprint, reused) = match reused {
        Some(cached) => (cached.fingerprint.clone(), true),
        None => (content_fingerprint(source_root, version, &paths), false),
    };
    json!({ "tree_sig": tree_sig, "fingerprint": fingerprint, "reused": reused })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The files that make up the runtime's identity, sorted by path.
///
/// A static asset that is also a `*.py` file is listed twice, as the walk
/// that defined this identity listed it.
pub(crate) fn identity_paths(source_root: &Path) -> Vec<PathBuf> {
    let package = source_root.join(PACKAGE);
    let mut paths = Vec::new();
    walk(&package, &mut |path| {
        if python_name(path) {
            paths.push(path.to_path_buf());
        }
    });
    let manifest = package.join("_native").join("runtime-manifest.json");
    if manifest.is_file() {
        paths.push(manifest);
    }
    let assets = package.join("guard").join("daemon").join("static");
    if assets.is_dir() {
        walk(&assets, &mut |path| {
            if path.is_file() {
                paths.push(path.to_path_buf());
            }
        });
    }
    paths.sort_by_cached_key(|path| sort_key(path));
    paths
}

/// Every entry below `root`, descending into real directories only: a
/// symlinked directory is listed but not entered.
fn walk(root: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        visit(&path);
        if kind.is_dir() {
            walk(&path, visit);
        }
    }
}

#[cfg(not(windows))]
fn python_name(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_encoded_bytes().ends_with(b".py"))
}

#[cfg(windows)]
fn python_name(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().to_lowercase().ends_with(".py"))
}

/// Paths compare component by component, case-folded where the file system
/// folds case.
fn sort_key(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| {
            let text = component.as_os_str().to_string_lossy();
            if cfg!(windows) {
                text.to_lowercase()
            } else {
                text.into_owned()
            }
        })
        .collect()
}

fn relative(source_root: &Path, path: &Path) -> String {
    path.strip_prefix(source_root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[cfg(unix)]
fn modified_ns(metadata: &fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())
}

#[cfg(not(unix))]
fn modified_ns(metadata: &fs::Metadata) -> i128 {
    use std::time::UNIX_EPOCH;
    metadata
        .modified()
        .map_or(0, |time| match time.duration_since(UNIX_EPOCH) {
            Ok(after) => after.as_nanos() as i128,
            Err(before) => -(before.duration().as_nanos() as i128),
        })
}

/// Path, size and modification time of each file that can be read.
fn tree_signature(source_root: &Path, version: &str, paths: &[PathBuf]) -> String {
    let mut digest = Sha256::new();
    digest.update(version.as_bytes());
    for path in paths {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        digest.update(relative(source_root, path).as_bytes());
        digest.update(metadata.len().to_string().as_bytes());
        digest.update(modified_ns(&metadata).to_string().as_bytes());
    }
    hex::encode(digest.finalize())
}

/// Path, size and bytes of each file. A file that stops reading part way
/// still contributes what was read.
fn content_fingerprint(source_root: &Path, version: &str, paths: &[PathBuf]) -> String {
    let mut digest = Sha256::new();
    digest.update(version.as_bytes());
    let mut chunk = vec![0_u8; CHUNK_BYTES];
    for path in paths {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        digest.update(relative(source_root, path).as_bytes());
        digest.update(metadata.len().to_string().as_bytes());
        let Ok(mut file) = File::open(path) else {
            continue;
        };
        while let Ok(read) = file.read(&mut chunk) {
            if read == 0 {
                break;
            }
            digest.update(&chunk[..read]);
        }
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
#[path = "runtime_fingerprint_tests.rs"]
mod tests;
