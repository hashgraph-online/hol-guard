//! `runtime-fingerprint --stdin`: the identity of an installed Guard source
//! tree, for daemon compatibility (`guard/daemon/manager.py` memoises the
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

use crate::managed_resident;

const SCHEMA: &str = "runtime-fingerprint.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
/// The private-file reader's size bound, which the cache has always kept to.
const MAX_CACHE_BYTES: u64 = 4096;
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

fn invalid() -> String {
    "runtime_fingerprint_request_invalid".to_owned()
}

fn answer(
    source_root: &Path,
    version: &str,
    cached: Option<Cached>,
    cache: Option<&CacheFile>,
) -> Value {
    let paths = identity_paths(source_root);
    let tree_sig = tree_signature(source_root, version, &paths);
    let cached = cached.or_else(|| cache.and_then(CacheFile::load));
    let reused =
        cached.filter(|cached| cached.tree_sig == tree_sig && is_sha256_hex(&cached.fingerprint));
    let (fingerprint, reused) = match reused {
        Some(cached) => (cached.fingerprint, true),
        None => {
            let fingerprint = content_fingerprint(source_root, version, &paths);
            if let Some(cache) = cache {
                cache.store(&tree_sig, &fingerprint);
            }
            (fingerprint, false)
        }
    };
    json!({ "tree_sig": tree_sig, "fingerprint": fingerprint, "reused": reused })
}

/// The on-disk form of the cache, keyed by the source root it describes.
/// Unknown keys are ignored.
#[derive(Deserialize)]
struct Stored {
    content_fingerprint: String,
    source_root: String,
    tree_sig: String,
}

struct CacheFile {
    directory: PathBuf,
    path: PathBuf,
    private_root: PathBuf,
    source_root: String,
}

impl CacheFile {
    fn new(directory: &str, source_root: &str) -> Option<Self> {
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            return None;
        }
        let private_root = directory.parent()?.to_path_buf();
        let name = format!(
            "{}.json",
            hex::encode(Sha256::digest(source_root.as_bytes()))
        );
        Some(Self {
            path: directory.join(name),
            directory,
            private_root,
            source_root: source_root.to_owned(),
        })
    }

    fn load(&self) -> Option<Cached> {
        let bytes = read_cache(&self.directory, &self.path, &self.private_root)?;
        let stored: Stored = serde_json::from_slice(&bytes).ok()?;
        (stored.source_root == self.source_root && is_sha256_hex(&stored.content_fingerprint))
            .then_some(Cached {
                tree_sig: stored.tree_sig,
                fingerprint: stored.content_fingerprint,
            })
    }

    fn store(&self, tree_sig: &str, fingerprint: &str) {
        #[cfg(not(windows))]
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            if builder.create(&self.private_root).is_err() {
                return;
            }
        }
        if crate::resident_state::ensure_private_directory_under(
            &self.directory,
            &self.private_root,
            true,
        )
        .is_err()
        {
            return;
        }
        let body = json!({
            "content_fingerprint": fingerprint,
            "source_root": self.source_root,
            "tree_sig": tree_sig,
        });
        let _ = managed_resident::private_file::write_private(
            &self.path,
            body.to_string().as_bytes(),
            &self.private_root,
        );
    }
}

/// The cache file's bytes. The directory is opened without following a
/// final link and must be a directory the effective user owns that no one
/// else can enter; the file is then opened relative to that handle, so a
/// directory swapped after the check is never read, and it too must be a
/// private regular file the effective user owns.
#[cfg(unix)]
fn read_cache(directory: &Path, path: &Path, _private_root: &Path) -> Option<Vec<u8>> {
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;

    let euid = nix::unistd::geteuid().as_raw();
    let private = |metadata: &fs::Metadata| {
        metadata.uid() == euid && metadata.permissions().mode() & 0o077 == 0
    };
    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .ok()?;
    let metadata = handle.metadata().ok()?;
    if !metadata.is_dir() || !private(&metadata) {
        return None;
    }
    let fd = openat(
        handle.as_fd(),
        path.file_name()?,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let file = File::from(fd);
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || !private(&metadata)
        || metadata.nlink() != 1
        || metadata.len() > MAX_CACHE_BYTES
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_CACHE_BYTES).then_some(bytes)
}

#[cfg(not(unix))]
fn read_cache(directory: &Path, path: &Path, private_root: &Path) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    managed_resident::private_file::read_private_bytes(
        path,
        private_root,
        "runtime_fingerprint_cache",
    )
    .ok()?
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
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => digest.update(&chunk[..read]),
                // A signal mid-read is not the end of the file.
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
#[path = "runtime_fingerprint_tests.rs"]
mod tests;
