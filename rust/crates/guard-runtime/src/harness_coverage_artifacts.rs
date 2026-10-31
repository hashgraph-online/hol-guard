//! Bounded, race-aware evidence for the files a managed harness installed in a
//! user's home.
//!
//! An artifact that cannot be read, changed while it was read, or is reached
//! through a link is missing: evidence is only ever taken from a file or a
//! directory tree that held still for the whole read.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 128;
const MAX_MANIFEST_DEPTH: usize = 16;
const MAX_MANIFEST_NODES: usize = 2048;
/// Links followed while resolving one path before it is taken as spelled.
const MAX_LINK_HOPS: usize = 40;
const PATH_KEYS: [&str; 7] = [
    "config_path",
    "extension_path",
    "hook_path",
    "managed_config_path",
    "plugin_path",
    "shim_path",
    "shim_paths",
];

/// What an artifact is now. `None` from [`artifact_digest`] means missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Evidence {
    File(String),
    Directory(String),
}

/// The SHA-256 of a regular file, or of every entry of a directory tree.
pub(super) fn artifact_digest(path: &Path) -> Option<Evidence> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return None;
    }
    if file_type.is_dir() {
        let digest = directory_digest(path)?;
        let after = fs::symlink_metadata(path).ok()?;
        // A directory's size moves with its entries, which the digest covers.
        if !after.is_dir() || stamp(&metadata).1 != stamp(&after).1 {
            return None;
        }
        return Some(Evidence::Directory(digest));
    }
    file_digest(path, &metadata).map(Evidence::File)
}

fn file_digest(path: &Path, metadata: &Metadata) -> Option<String> {
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        return None;
    }
    let mut file = open_without_following(path).ok()?;
    let before = file.metadata().ok()?;
    if !before.is_file() || before.len() > MAX_ARTIFACT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(before.len())
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 != before.len() {
        return None;
    }
    let after = file.metadata().ok()?;
    drop(file);
    let last = fs::symlink_metadata(path).ok()?;
    let expected = stamp(metadata);
    if !last.is_file()
        || [&before, &after, &last]
            .into_iter()
            .any(|seen| stamp(seen) != expected)
    {
        return None;
    }
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Open `path` for reading without following a link at its last component.
#[cfg(unix)]
pub(super) fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
pub(super) fn open_without_following(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// A file's size, then every other field that must hold still while it is read.
pub(super) type Stamp = (u64, [i128; 6]);

#[cfg(unix)]
pub(super) fn stamp(metadata: &Metadata) -> Stamp {
    use std::os::unix::fs::MetadataExt;

    (
        metadata.size(),
        [
            i128::from(metadata.dev()),
            i128::from(metadata.ino()),
            i128::from(metadata.mtime()),
            i128::from(metadata.mtime_nsec()),
            i128::from(metadata.ctime()),
            i128::from(metadata.ctime_nsec()),
        ],
    )
}

#[cfg(not(unix))]
pub(super) fn stamp(metadata: &Metadata) -> Stamp {
    let nanos = |time: io::Result<std::time::SystemTime>| {
        time.ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(-1, |elapsed| elapsed.as_nanos() as i128)
    };
    (
        metadata.len(),
        [
            nanos(metadata.modified()),
            nanos(metadata.created()),
            0,
            0,
            0,
            0,
        ],
    )
}

/// Every directory and file below `root`, depth first in name order, each
/// file with its own digest. A link, a special file, or a tree past its
/// bounds has no digest, and neither does an empty one.
fn directory_digest(root: &Path) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut total_bytes = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut names: Vec<OsString> = Vec::new();
        for entry in fs::read_dir(&directory).ok()? {
            names.push(entry.ok()?.file_name());
        }
        if entries.len() + names.len() > MAX_DIRECTORY_ENTRIES {
            return None;
        }
        names.sort();
        let mut directories: Vec<PathBuf> = Vec::new();
        let mut files: Vec<(PathBuf, Metadata)> = Vec::new();
        for name in names {
            let candidate = directory.join(name);
            let metadata = fs::symlink_metadata(&candidate).ok()?;
            if metadata.is_dir() {
                directories.push(candidate);
            } else if metadata.is_file() {
                files.push((candidate, metadata));
            } else {
                return None;
            }
        }
        for candidate in &directories {
            entries.push(format!("d:{}", relative_text(candidate, root)?));
        }
        for (candidate, metadata) in &files {
            total_bytes += metadata.len();
            if total_bytes > MAX_DIRECTORY_BYTES {
                return None;
            }
            let digest = file_digest(candidate, metadata)?;
            entries.push(format!("f:{}:{digest}", relative_text(candidate, root)?));
        }
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return None;
        }
        pending.extend(directories.into_iter().rev());
    }
    if entries.is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(entries.join("\n").as_bytes())))
}

/// `path` below `root`, spelled with this platform's separator.
pub(super) fn relative_text(path: &Path, root: &Path) -> Option<String> {
    path.strip_prefix(root).ok()?.to_str().map(str::to_owned)
}

/// The files a harness install manifest names below `home`, sorted, at most
/// `limit` of them, each spelled from the resolved home. `Err` is a manifest
/// past its depth or node bounds.
pub(super) fn managed_manifest_paths(
    manifest: &Map<String, Value>,
    home: &Path,
    limit: usize,
) -> Result<Vec<PathBuf>, ()> {
    let candidates = manifest_path_values(manifest)?;
    let home = resolve_lenient(home);
    let mut paths = BTreeSet::new();
    for raw in candidates {
        let spelled = if raw == "~" {
            home.clone()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            home.join(rest)
        } else {
            home.join(raw)
        };
        let candidate = normalize_lexically(&spelled);
        let normalized = resolve_lenient(&candidate);
        if normalized != home && normalized.starts_with(&home) {
            paths.insert(candidate);
        }
    }
    Ok(paths.into_iter().take(limit).collect())
}

fn manifest_path_values(manifest: &Map<String, Value>) -> Result<Vec<&str>, ()> {
    let mut candidates = Vec::new();
    let mut pending: Vec<(&Value, usize)> = Vec::new();
    let mut visited = 1;
    collect_mapping(manifest, 0, &mut candidates, &mut pending)?;
    while let Some((value, depth)) = pending.pop() {
        visited += 1;
        if visited > MAX_MANIFEST_NODES || depth > MAX_MANIFEST_DEPTH {
            return Err(());
        }
        match value {
            Value::Object(mapping) => {
                collect_mapping(mapping, depth, &mut candidates, &mut pending)?
            }
            Value::Array(items) => {
                if items.len() > MAX_MANIFEST_NODES {
                    return Err(());
                }
                pending.extend(items.iter().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(candidates)
}

fn collect_mapping<'a>(
    mapping: &'a Map<String, Value>,
    depth: usize,
    candidates: &mut Vec<&'a str>,
    pending: &mut Vec<(&'a Value, usize)>,
) -> Result<(), ()> {
    if mapping.len() > MAX_MANIFEST_NODES {
        return Err(());
    }
    for (key, item) in mapping {
        if PATH_KEYS.contains(&key.as_str()) {
            match item {
                Value::String(text) if !text.trim().is_empty() => candidates.push(text),
                Value::Array(entries) => candidates.extend(
                    entries
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|text| !text.trim().is_empty()),
                ),
                _ => {}
            }
        } else if item.is_object() || item.is_array() {
            pending.push((item, depth + 1));
        }
    }
    Ok(())
}

/// `os.path.abspath` for a path that is already absolute: `.` dropped and
/// `..` applied to the spelling, without touching the filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// `Path.resolve(strict=False)`: every link along the path is followed while
/// the path exists, and the rest is applied as spelled.
pub(super) fn resolve_lenient(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    let mut pending: Vec<OsString> = path
        .components()
        .rev()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    let mut hops = 0;
    while let Some(part) = pending.pop() {
        let component = Path::new(&part).components().next();
        match component {
            Some(Component::Prefix(_) | Component::RootDir) => resolved.push(&part),
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            Some(Component::Normal(name)) => {
                let next = resolved.join(name);
                let is_link =
                    fs::symlink_metadata(&next).is_ok_and(|metadata| metadata.is_symlink());
                let target = if is_link && hops < MAX_LINK_HOPS {
                    fs::read_link(&next).ok()
                } else {
                    None
                };
                match target {
                    Some(target) => {
                        hops += 1;
                        if target.is_absolute() {
                            resolved = PathBuf::new();
                        }
                        pending.extend(
                            target
                                .components()
                                .rev()
                                .map(|component| component.as_os_str().to_owned()),
                        );
                    }
                    None => resolved = next,
                }
            }
            Some(Component::CurDir) | None => {}
        }
    }
    resolved
}
