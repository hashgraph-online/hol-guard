//! `runtime-fingerprint --stdin`: the identity of an installed Guard source
//! tree, for daemon compatibility (the retired Python `manager.py` memoises the
//! answer for the life of its process).
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
//! hash. The cache is either the request's `cached` pair or, given a
//! `cache_dir`, a private JSON file there named by the SHA-256 of the
//! source root. On Unix the file is opened relative to the directory handle
//! that passed the owner and mode checks, and both must belong to the
//! effective user, so a foreign or swapped file is never trusted; Windows
//! reads it through the resident's private-file checks. A freshly hashed
//! tree rewrites it. A cache that cannot be read or written, or a
//! `cache_dir` that cannot hold one, only costs the content hash.

use std::fs::{self, File};
use std::io::{ErrorKind, Read};
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
    #[serde(default)]
    cache_dir: Option<String>,
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
    let cache = request
        .cache_dir
        .as_deref()
        .and_then(|directory| CacheFile::new(directory, &request.source_root));
    Ok(answer(
        &source_root,
        &request.version,
        request.cached,
        cache.as_ref(),
    )
    .to_string()
    .into_bytes())
}

/// Whether `fingerprint`, a daemon's identity, is the one `version` has over
/// the tree now installed at `source_root`. A long-lived caller that cached
/// its own identity before an in-place upgrade asks this before retiring the
/// daemon the upgrade started. A tree with a file that cannot be read is
/// never a match.
pub(crate) fn runs_installed_tree(
    source_root: Option<&str>,
    version: Option<&str>,
    fingerprint: &str,
) -> bool {
    let (Some(source_root), Some(version)) = (
        source_root.filter(|root| !root.trim().is_empty()),
        version.filter(|version| !version.trim().is_empty()),
    ) else {
        return false;
    };
    let root = Path::new(source_root);
    root.is_absolute()
        && root.join(PACKAGE).is_dir()
        && installed_fingerprint(source_root, version, default_cache_dir().as_deref())
            .is_some_and(|installed| installed == fingerprint)
}

/// The cache directory the Python caller names in its requests,
/// `Path.home() / ".hol-guard" / "runtime-fingerprint-cache"`, so a check
/// from a new `daemon-manage` process reuses the hash a starting process
/// already paid for. Tests never touch the user's.
fn default_cache_dir() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    crate::claude_hook_bridge::home_directory()
        .map(|home| home.join(".hol-guard").join("runtime-fingerprint-cache"))
}

/// The `runtime-fingerprint` answer for the installed tree, or `None` when
/// a file could not be read; such a digest is neither returned nor cached.
pub(crate) fn installed_fingerprint(
    source_root: &str,
    version: &str,
    cache_dir: Option<&Path>,
) -> Option<String> {
    let root = Path::new(source_root);
    let cache = cache_dir
        .and_then(|directory| directory.to_str())
        .and_then(|directory| CacheFile::new(directory, source_root));
    let (paths, listed) = identity_paths(root);
    let (tree_sig, signed) = tree_signature(root, version, &paths);
    if !listed || !signed {
        return None;
    }
    if let Some(cached) = cache.as_ref().and_then(CacheFile::load) {
        if cached.tree_sig == tree_sig {
            return Some(cached.fingerprint);
        }
    }
    let (fingerprint, complete) = content_fingerprint(root, version, &paths);
    if !complete || !unchanged_since(root, version, &paths, &tree_sig) {
        return None;
    }
    if let Some(cache) = cache {
        cache.store(&tree_sig, &fingerprint);
    }
    Some(fingerprint)
}

/// Whether the tree still has the signature taken before its content was
/// read. A module replaced between the two passes would otherwise pair one
/// tree's signature with another tree's digest in the cache.
fn unchanged_since(root: &Path, version: &str, paths: &[PathBuf], tree_sig: &str) -> bool {
    let (paths_now, listed) = identity_paths(root);
    let (signature, signed) = tree_signature(root, version, &paths_now);
    listed && signed && paths_now == paths && signature == tree_sig
}

fn invalid() -> String {
    "runtime_fingerprint_request_invalid".to_owned()
}

fn answer(
    source_root: &Path,
    version: &str,
    cached: Option<Cached>,
    cache: Option<&CacheFile>,
) -> Value {
    let (paths, listed) = identity_paths(source_root);
    let (tree_sig, signed) = tree_signature(source_root, version, &paths);
    // A short listing or signature describes less than the digest would, so
    // it neither selects nor keys a cached digest; the answer stays best
    // effort.
    let whole = listed && signed;
    let cached = cached
        .or_else(|| cache.and_then(CacheFile::load))
        .filter(|_| whole);
    let reused =
        cached.filter(|cached| cached.tree_sig == tree_sig && is_sha256_hex(&cached.fingerprint));
    let (fingerprint, reused) = match reused {
        Some(cached) => (cached.fingerprint, true),
        None => {
            let (fingerprint, complete) = content_fingerprint(source_root, version, &paths);
            if let (Some(cache), true) = (cache, whole && complete) {
                if unchanged_since(source_root, version, &paths, &tree_sig) {
                    cache.store(&tree_sig, &fingerprint);
                }
            }
            (fingerprint, false)
        }
    };
    json!({ "tree_sig": tree_sig, "fingerprint": fingerprint, "reused": reused })
}

pub(super) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The files that make up the runtime's identity, sorted by path, and
/// whether every directory and probed path of the listing could be read.
///
/// A static asset that is also a `*.py` file is listed twice, as the walk
/// that defined this identity listed it.
fn identity_paths(source_root: &Path) -> (Vec<PathBuf>, bool) {
    let package = source_root.join(PACKAGE);
    let mut paths = Vec::new();
    let mut complete = walk(&package, &mut |path| {
        if python_name(path) {
            paths.push(path.to_path_buf());
        }
    });
    let manifest = package.join("_native").join("runtime-manifest.json");
    match target_metadata(&manifest) {
        Ok(Some(metadata)) if metadata.is_file() => paths.push(manifest),
        Ok(_) => {}
        Err(()) => complete = false,
    }
    let assets = package.join("guard").join("daemon").join("static");
    match target_metadata(&assets) {
        Ok(Some(metadata)) if metadata.is_dir() => {
            let mut hidden = false;
            let listed = walk(&assets, &mut |path| match target_metadata(path) {
                Ok(Some(metadata)) if metadata.is_file() => paths.push(path.to_path_buf()),
                Ok(_) => {}
                Err(()) => hidden = true,
            });
            complete &= listed && !hidden;
        }
        Ok(_) => {}
        Err(()) => complete = false,
    }
    paths.sort_by_cached_key(|path| sort_key(path));
    (paths, complete)
}

/// The metadata of what `path` names, following links. `None` when nothing
/// is there (a missing path or a dangling link); an error that hides whether
/// something is there, such as a directory that cannot be searched, is
/// `Err`, so the listing is not taken as whole.
fn target_metadata(path: &Path) -> Result<Option<fs::Metadata>, ()> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(_) => Err(()),
    }
}

/// Every entry below `root`, descending into real directories only: a
/// symlinked directory is listed but not entered. False when a directory or
/// entry could not be read, so the listing may be short.
fn walk(root: &Path, visit: &mut dyn FnMut(&Path)) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        let Ok(kind) = entry.file_type() else {
            complete = false;
            continue;
        };
        let path = entry.path();
        visit(&path);
        if kind.is_dir() {
            complete &= walk(&path, visit);
        }
    }
    complete
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
/// Also whether every path's metadata could be read.
fn tree_signature(source_root: &Path, version: &str, paths: &[PathBuf]) -> (String, bool) {
    let mut digest = Sha256::new();
    digest.update(version.as_bytes());
    let mut complete = true;
    for path in paths {
        let Ok(metadata) = fs::metadata(path) else {
            complete = false;
            continue;
        };
        digest.update(relative(source_root, path).as_bytes());
        digest.update(metadata.len().to_string().as_bytes());
        digest.update(modified_ns(&metadata).to_string().as_bytes());
    }
    (hex::encode(digest.finalize()), complete)
}

/// Path, size and bytes of each file, and whether every file was read in
/// full. A file that stops reading part way still contributes what was
/// read; such a digest is answered but never cached. An entry that is not a
/// regular file contributes its path and size only, and is opened without
/// blocking, so a named pipe cannot hold the answer.
fn content_fingerprint(source_root: &Path, version: &str, paths: &[PathBuf]) -> (String, bool) {
    let mut digest = Sha256::new();
    digest.update(version.as_bytes());
    let mut chunk = vec![0_u8; CHUNK_BYTES];
    let mut complete = true;
    for path in paths {
        let Ok(metadata) = fs::metadata(path) else {
            complete = false;
            continue;
        };
        digest.update(relative(source_root, path).as_bytes());
        digest.update(metadata.len().to_string().as_bytes());
        if !metadata.is_file() {
            continue;
        }
        let Ok(mut file) = open_identity_file(path) else {
            complete = false;
            continue;
        };
        match file.metadata() {
            Ok(opened) if opened.is_file() => {}
            Ok(_) => continue,
            Err(_) => {
                complete = false;
                continue;
            }
        }
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => digest.update(&chunk[..read]),
                // A signal mid-read is not the end of the file.
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    complete = false;
                    break;
                }
            }
        }
    }
    (hex::encode(digest.finalize()), complete)
}

fn open_identity_file(path: &Path) -> std::io::Result<File> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options.open(path)
}

#[path = "runtime_fingerprint_cache.rs"]
mod cache;
use cache::CacheFile;

#[cfg(test)]
#[path = "runtime_fingerprint_tests.rs"]
mod tests;
