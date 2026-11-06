//! Bounded identities for reusable local Node routine approvals.

use std::collections::BTreeSet;
use std::fs;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{framed_digest, probe, Abort, Outcome};
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_interpreter_trust::resolve_strict;

const MAX_PACKAGE_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CLOSURE_PACKAGES: usize = 1_000;
const MAX_CLOSURE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CLOSURE_FILES: u64 = 50_000;
const DEPENDENCY_SECTIONS: [&str; 3] = ["dependencies", "optionalDependencies", "peerDependencies"];
const TREE_PREFIX: &[u8] = b"hol-guard:package-tree:v1\0";

/// Files and bytes hashed so far across one dependency closure.
#[derive(Default)]
pub(super) struct TreeBudget {
    files: u64,
    size: u64,
}

/// A bounded, non-symlink UTF-8 text file read with universal newlines.
pub(super) fn read_bounded_text(path: &PyPath) -> Option<String> {
    if probe(path, pyfs::is_symlink).ok()? || !probe(path, pyfs::is_file).ok()? {
        return None;
    }
    if fs::metadata(path.to_string()).ok()?.len() > MAX_PACKAGE_JSON_BYTES {
        return None;
    }
    let text = String::from_utf8(fs::read(path.to_string()).ok()?).ok()?;
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `read_package_json`: a bounded, non-symlink JSON object, or nothing.
pub(super) fn read_package_json(path: &PyPath) -> Option<Map<String, Value>> {
    match serde_json::from_str(&read_bounded_text(path)?).ok()? {
        Value::Object(package) => Some(package),
        _ => None,
    }
}

/// `routine_workspace_identity`: the canonical workspace directory's identity.
pub(super) fn workspace_identity(workspace: &PyPath) -> Outcome<Value> {
    let canonical = resolve_strict(workspace).ok_or(Abort)?;
    stat_identity(&canonical)
}

#[cfg(unix)]
fn stat_identity(canonical: &PyPath) -> Outcome<Value> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(canonical.to_string()).map_err(|_| Abort)?;
    Ok(json!({
        "canonical_path": canonical.to_string(),
        "device": metadata.dev(),
        "inode": metadata.ino(),
    }))
}

/// The directory's volume serial and file ID, read from an opened handle.
#[cfg(windows)]
fn stat_identity(canonical: &PyPath) -> Outcome<Value> {
    let id = guard_runtime_windows_process::directory_file_id(std::path::Path::new(
        &canonical.to_string(),
    ))
    .map_err(|_| Abort)?;
    Ok(json!({
        "canonical_path": canonical.to_string(),
        "file_id": id.to_hex(),
    }))
}

#[cfg(not(any(unix, windows)))]
fn stat_identity(_canonical: &PyPath) -> Outcome<Value> {
    Err(Abort)
}

/// `routine_dependency_closure_digest`: every installed package reachable
/// from the routine runner and its configuration imports.
pub(super) fn dependency_closure_digest(workspace: &PyPath, roots: &[String]) -> Outcome<String> {
    let node_modules = resolve_strict(&workspace.join("node_modules")).ok_or(Abort)?;
    let mut pending: Vec<String> = roots.to_vec();
    let mut budget = TreeBudget::default();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut records: Vec<(String, String, String)> = Vec::new();
    while let Some(name) = pending.pop() {
        if visited.contains(&name) {
            continue;
        }
        if visited.len() >= MAX_CLOSURE_PACKAGES {
            return Err(Abort);
        }
        let package_dir = node_modules.join(&name);
        if probe(&package_dir, pyfs::is_symlink)? || !probe(&package_dir, pyfs::is_dir)? {
            return Err(Abort);
        }
        let canonical = resolve_strict(&package_dir).ok_or(Abort)?;
        canonical.relative_to(&node_modules).ok_or(Abort)?;
        let package = read_package_json(&canonical.join("package.json")).ok_or(Abort)?;
        if package.get("name").and_then(Value::as_str) != Some(name.as_str()) {
            return Err(Abort);
        }
        let version = package
            .get("version")
            .and_then(Value::as_str)
            .ok_or(Abort)?
            .to_owned();
        visited.insert(name.clone());
        let digest = package_tree_digest(&canonical, true, &mut budget)?;
        records.push((name, version, digest));
        for dependency in dependency_names(&package) {
            if probe(&node_modules.join(&dependency), pyfs::is_dir)? {
                pending.push(dependency);
            }
        }
    }
    records.sort();
    let encoded: Vec<Value> = records
        .into_iter()
        .map(|(name, version, digest)| json!([name, version, digest]))
        .collect();
    framed_digest(b"hol-guard:node-closure:v1\0", &Value::Array(encoded))
}

fn dependency_names(package: &Map<String, Value>) -> BTreeSet<String> {
    DEPENDENCY_SECTIONS
        .iter()
        .filter_map(|section| package.get(*section).and_then(Value::as_object))
        .flat_map(|dependencies| dependencies.keys().cloned())
        .collect()
}

/// `routine_package_tree_digest`: an installed package tree hashed with the
/// bounded, canonical `os.walk` traversal.
pub(super) fn package_tree_digest(
    root: &PyPath,
    skip_nested_bin: bool,
    budget: &mut TreeBudget,
) -> Outcome<String> {
    let canonical_root = resolve_strict(root).ok_or(Abort)?;
    if probe(root, pyfs::is_symlink)? || !probe(&canonical_root, pyfs::is_dir)? {
        return Err(Abort);
    }
    tree_walk::digest(&canonical_root.to_string(), skip_nested_bin, budget)
}

mod tree_walk {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::{self, Read};
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::{framed_bytes, Abort, Outcome, TreeBudget, MAX_CLOSURE_BYTES, MAX_CLOSURE_FILES};
    use crate::codex_output_fs::ignorable;

    /// A directory entry: its name as Python code points (`surrogateescape`)
    /// for sorting and encoding, and its raw name for filesystem access.
    type Entry = (Vec<u32>, OsString);

    /// `os.walk(root, followlinks=False)` (CPython 3.12): pre-order, sorted
    /// names, unreadable directories skipped, symlinks refused.
    pub(super) fn digest(
        root: &str,
        skip_nested_bin: bool,
        budget: &mut TreeBudget,
    ) -> Outcome<String> {
        let mut records: Vec<(Vec<u32>, String)> = Vec::new();
        let mut stack: Vec<(PathBuf, Vec<u32>)> = vec![(PathBuf::from(root), Vec::new())];
        while let Some((directory, relative)) = stack.pop() {
            let Some((mut directories, mut files)) = scan(&directory) else {
                continue;
            };
            // Names are unique, so the decoded name alone decides the order.
            directories.sort();
            files.sort();
            let in_node_modules = directory
                .file_name()
                .is_some_and(|name| name == OsStr::new("node_modules"));
            if skip_nested_bin && in_node_modules {
                if let Some(index) = directories
                    .iter()
                    .position(|(_, name)| name == OsStr::new(".bin"))
                {
                    directories.remove(index);
                }
            }
            for (_, name) in &directories {
                if is_symlink(&directory.join(name))? {
                    return Err(Abort);
                }
            }
            for (key, name) in &files {
                let path = directory.join(name);
                if is_symlink(&path)? {
                    return Err(Abort);
                }
                let metadata = fs::metadata(&path).map_err(|_| Abort)?;
                if !metadata.is_file() {
                    return Err(Abort);
                }
                budget.files += 1;
                budget.size += metadata.len();
                if budget.files > MAX_CLOSURE_FILES || budget.size > MAX_CLOSURE_BYTES {
                    return Err(Abort);
                }
                records.push((join(&relative, key), file_sha256(&path)?));
            }
            for (key, name) in directories.into_iter().rev() {
                stack.push((directory.join(&name), join(&relative, &key)));
            }
        }
        let mut encoded = String::from("[");
        for (index, (path, digest)) in records.iter().enumerate() {
            if index > 0 {
                encoded.push(',');
            }
            encoded.push('[');
            push_json_string(&mut encoded, path);
            encoded.push_str(",\"");
            encoded.push_str(digest);
            encoded.push_str("\"]");
        }
        encoded.push(']');
        Ok(framed_bytes(super::TREE_PREFIX, encoded.as_bytes()))
    }

    /// `scandir` plus `DirEntry.is_dir()`; a failed listing skips the directory.
    fn scan(directory: &Path) -> Option<(Vec<Entry>, Vec<Entry>)> {
        let mut directories = Vec::new();
        let mut files = Vec::new();
        for entry in fs::read_dir(directory).ok()? {
            let entry = entry.ok()?;
            let is_dir = match entry.file_type() {
                Ok(kind) if kind.is_symlink() => {
                    fs::metadata(entry.path()).is_ok_and(|metadata| metadata.is_dir())
                }
                Ok(kind) => kind.is_dir(),
                Err(_) => false,
            };
            let name = entry.file_name();
            let key = code_points(&name);
            if is_dir {
                directories.push((key, name));
            } else {
                files.push((key, name));
            }
        }
        Some((directories, files))
    }

    /// `Path.is_symlink()`: "not there" is `False`, other errors raise.
    fn is_symlink(path: &Path) -> Outcome<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(metadata.file_type().is_symlink()),
            Err(error) if ignorable(&error) => Ok(false),
            Err(_) => Err(Abort),
        }
    }

    fn file_sha256(path: &Path) -> Outcome<String> {
        let mut file = fs::File::open(path).map_err(|_| Abort)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Abort),
            };
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn join(relative: &[u32], name: &[u32]) -> Vec<u32> {
        if relative.is_empty() {
            return name.to_vec();
        }
        let mut joined = relative.to_vec();
        joined.push(u32::from('/'));
        joined.extend_from_slice(name);
        joined
    }

    /// A name as the Python `str` `os.scandir` yields: the UTF-16 code units
    /// decoded, with each unpaired surrogate kept as its own code point.
    #[cfg(windows)]
    fn code_points(name: &OsStr) -> Vec<u32> {
        use std::os::windows::ffi::OsStrExt;

        char::decode_utf16(name.encode_wide())
            .map(|unit| unit.map_or_else(|error| u32::from(error.unpaired_surrogate()), u32::from))
            .collect()
    }

    #[cfg(unix)]
    fn code_points(name: &OsStr) -> Vec<u32> {
        use std::os::unix::ffi::OsStrExt;

        surrogateescape(name.as_bytes())
    }

    /// The file-system decoding Python applies to names: UTF-8 with each
    /// undecodable byte mapped to the lone surrogate `U+DC00 + byte`.
    #[cfg(unix)]
    fn surrogateescape(mut bytes: &[u8]) -> Vec<u32> {
        let mut points = Vec::new();
        loop {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    points.extend(text.chars().map(u32::from));
                    return points;
                }
                Err(error) => {
                    let (valid, rest) = bytes.split_at(error.valid_up_to());
                    points.extend(
                        std::str::from_utf8(valid)
                            .unwrap_or("")
                            .chars()
                            .map(u32::from),
                    );
                    let invalid = error.error_len().unwrap_or(rest.len());
                    points.extend(rest[..invalid].iter().map(|byte| 0xDC00 + u32::from(*byte)));
                    bytes = &rest[invalid..];
                }
            }
        }
    }

    /// `json.dumps` string encoding with `ensure_ascii=True`.
    fn push_json_string(out: &mut String, points: &[u32]) {
        out.push('"');
        for &point in points {
            match point {
                0x22 => out.push_str("\\\""),
                0x5C => out.push_str("\\\\"),
                0x0A => out.push_str("\\n"),
                0x0D => out.push_str("\\r"),
                0x09 => out.push_str("\\t"),
                0x08 => out.push_str("\\b"),
                0x0C => out.push_str("\\f"),
                0x20..=0x7E => out.push(char::from(point as u8)),
                0x10000.. => {
                    let value = point - 0x10000;
                    let high = 0xD800 | (value >> 10);
                    let low = 0xDC00 | (value & 0x3FF);
                    out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                }
                _ => out.push_str(&format!("\\u{point:04x}")),
            }
        }
        out.push('"');
    }
}

/// `sha256(prefix + len(encoded).to_bytes(8, "big") + encoded).hexdigest()`.
fn framed_bytes(prefix: &[u8], encoded: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    hex::encode(hasher.finalize())
}
