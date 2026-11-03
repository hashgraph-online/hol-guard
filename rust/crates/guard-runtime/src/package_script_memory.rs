//! `runner_authority` kind `package_script_memory`: which package.json projects
//! Guard remembers for package-script recognition (`package_json_script_memory.py`
//! before it moved here).
//!
//! Python sends its working directory, expanded and absolute, with every
//! request; a relative remembered path is read against it, as before.
//!
//! - `roots` lists the project roots to refresh: the working directory when
//!   asked, then each remembered package-scripts project, each followed by the
//!   workspace packages its `package.json` names. A root is kept only while its
//!   `package.json` is a file, and the list stops growing past sixteen roots.
//! - `available` answers, for each listed item, whether it may still be shown:
//!   a package-scripts item drops out once its `package.json` is gone, unless a
//!   choice was saved for it.
//! - `operator_cwd` picks the directory a pasted command is read in: the
//!   operator's own directory when it exists, else the working directory when it
//!   sits in a package project, else the home.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use guard_command::codex_output_fnmatch::fnmatchcase;
use serde_json::{json, Map, Value};

use crate::guard_paths::python_realpath_lax;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SURFACE: &str = "package-scripts";
const MANIFEST: &str = "package.json";
const MAX_REMEMBERED: usize = 16;
const MAX_WORKSPACES: usize = 8;
const MAX_PATTERNS: usize = 6;
/// Directory levels walked looking for a package.json above the working directory.
const MAX_WALK: usize = 8;
/// Values that stand for a class of location rather than a remembered path.
const PATH_CLASS_TOKENS: [&str; 4] = ["unknown", "package-store", "system-bin", "user-tool"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "roots" => &["op", "cwd", "include_cwd", "entries"],
        "available" => &["op", "cwd", "entries"],
        "operator_cwd" => &["op", "cwd", "home", "requested"],
        _ => return Err(ERR_INVALID),
    };
    if fields.len() != keys.len() || !keys.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let cwd = absolute(fields, "cwd")?;
    match op {
        "roots" => {
            let include_cwd = fields
                .get("include_cwd")
                .and_then(Value::as_bool)
                .ok_or(ERR_INVALID)?;
            let entries = entries(fields)?;
            let roots = catalog_roots(&cwd, include_cwd, &entries);
            Ok(json!({ "roots": roots.iter().map(|root| text(root)).collect::<Vec<_>>() }))
        }
        "available" => {
            let entries = entries(fields)?;
            let available: Vec<bool> = entries
                .iter()
                .map(|entry| item_available(&cwd, entry))
                .collect();
            Ok(json!({ "available": available }))
        }
        _ => {
            let home = absolute(fields, "home")?;
            let requested = match fields.get("requested") {
                Some(Value::Null) => None,
                Some(Value::String(value)) if Path::new(value).is_absolute() => {
                    Some(PathBuf::from(value))
                }
                _ => return Err(ERR_INVALID),
            };
            let chosen = operator_cwd(&cwd, &home, requested.as_deref());
            Ok(json!({ "path": text(&chosen) }))
        }
    }
}

fn absolute(fields: &Map<String, Value>, key: &str) -> Result<PathBuf, &'static str> {
    let value = fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || value.contains('\0') {
        return Err(ERR_INVALID);
    }
    Ok(path)
}

fn entries(fields: &Map<String, Value>) -> Result<Vec<&Map<String, Value>>, &'static str> {
    fields
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|entry| entry.as_object().ok_or(ERR_INVALID))
        .collect()
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The remembered project path of a package-scripts item, if it names one.
fn remembered_path<'a>(entry: &'a Map<String, Value>) -> Option<&'a str> {
    if entry.get("surface").and_then(Value::as_str) != Some(SURFACE) {
        return None;
    }
    let raw = entry.get("source_path").and_then(Value::as_str)?;
    (!PATH_CLASS_TOKENS.contains(&raw)).then_some(raw)
}

fn is_manifest(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == MANIFEST)
}

fn manifest_of(path: &Path) -> PathBuf {
    if is_manifest(path) {
        path.to_path_buf()
    } else {
        path.join(MANIFEST)
    }
}

/// `Path.is_file()`: follows symlinks, and any error reads as not a file.
fn is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn is_dir(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

fn item_available(cwd: &Path, entry: &Map<String, Value>) -> bool {
    if matches!(
        entry.get("state").and_then(Value::as_str),
        Some("allowed" | "blocked")
    ) {
        return true;
    }
    match remembered_path(entry) {
        Some(raw) => is_file(&manifest_of(&cwd.join(raw))),
        None => true,
    }
}

fn catalog_roots(cwd: &Path, include_cwd: bool, entries: &[&Map<String, Value>]) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if include_cwd && is_dir(cwd) {
        candidates.push(cwd.to_path_buf());
    }
    for raw in entries.iter().filter_map(|entry| remembered_path(entry)) {
        let path = cwd.join(raw);
        let parent = path
            .parent()
            .filter(|_| is_manifest(&path))
            .map(Path::to_path_buf);
        candidates.push(parent.unwrap_or(path));
    }
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for candidate in candidates {
        let Ok(resolved) = python_realpath_lax(&candidate) else {
            continue;
        };
        let manifest = manifest_of(&resolved);
        if !is_file(&manifest) {
            continue;
        }
        let Some(root) = manifest.parent().map(Path::to_path_buf) else {
            continue;
        };
        if !seen.insert(root.clone()) {
            continue;
        }
        let children = workspace_package_roots(&root);
        roots.push(root);
        for child in children {
            if seen.insert(child.clone()) {
                roots.push(child);
            }
        }
        if roots.len() >= MAX_REMEMBERED {
            break;
        }
    }
    roots
}

/// The workspace packages a project's package.json names, as `Path.glob`
/// finds them; patterns that climb out of the project are skipped.
fn workspace_package_roots(root: &Path) -> Vec<PathBuf> {
    let Ok(bytes) = fs::read(root.join(MANIFEST)) else {
        return Vec::new();
    };
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    let listed = match payload.get("workspaces") {
        Some(Value::Array(items)) => Some(items),
        Some(Value::Object(object)) => object.get("packages").and_then(Value::as_array),
        _ => None,
    };
    let patterns: Vec<&str> = listed
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(MAX_PATTERNS)
        .collect();
    let mut found = Vec::new();
    for pattern in patterns {
        if pattern.contains("..") || pattern.starts_with('/') || pattern.contains("**") {
            continue;
        }
        for matched in glob(root, pattern) {
            if is_dir(&matched) && is_file(&matched.join(MANIFEST)) {
                found.push(matched);
            }
            if found.len() >= MAX_WORKSPACES {
                return found;
            }
        }
    }
    found
}

fn has_wildcard(part: &str) -> bool {
    part.contains(['*', '?', '['])
}

fn sort_key(path: &Path) -> String {
    let spelled = text(path);
    if cfg!(windows) {
        spelled.to_lowercase()
    } else {
        spelled
    }
}

/// `sorted(root.glob(pattern))` for a relative pattern without `**`: each
/// wildcard segment is matched with `fnmatch` against a directory's entries,
/// hidden ones included, and an empty or rooted pattern matches nothing.
fn glob(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut parts = Vec::new();
    for component in Path::new(pattern).components() {
        match component {
            Component::Normal(part) => match part.to_str() {
                Some(part) => parts.push(part),
                None => return Vec::new(),
            },
            Component::CurDir => {}
            _ => return Vec::new(),
        }
    }
    if parts.is_empty() {
        return Vec::new();
    }
    let mut current = vec![root.to_path_buf()];
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let mut next = Vec::new();
        for parent in &current {
            if !has_wildcard(part) {
                let child = parent.join(part);
                let present = if last {
                    fs::metadata(&child).is_ok()
                } else {
                    is_dir(&child)
                };
                if present {
                    next.push(child);
                }
                continue;
            }
            let Ok(listing) = fs::read_dir(parent) else {
                continue;
            };
            let names = listing
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok());
            for name in names {
                if !name_matches(&name, part) {
                    continue;
                }
                let child = parent.join(&name);
                if last || is_dir(&child) {
                    next.push(child);
                }
            }
        }
        current = next;
    }
    current.sort_by_key(|path| sort_key(path));
    current
}

fn name_matches(name: &str, pattern: &str) -> bool {
    if cfg!(windows) {
        fnmatchcase(&name.to_lowercase(), &pattern.to_lowercase())
    } else {
        fnmatchcase(name, pattern)
    }
}

/// `find_nearest_package_json` reached a package.json from `start`, stopping
/// at the home and after a few levels.
fn inside_package_project(start: &Path, home: &Path) -> bool {
    let Ok(mut current) = python_realpath_lax(start) else {
        return false;
    };
    let home = python_realpath_lax(home).ok();
    for _ in 0..MAX_WALK {
        if is_file(&current.join(MANIFEST)) {
            return true;
        }
        if home.as_deref() == Some(current.as_path()) {
            return false;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return false,
        }
    }
    false
}

fn operator_cwd(cwd: &Path, home: &Path, requested: Option<&Path>) -> PathBuf {
    if let Some(resolved) = requested.and_then(|path| python_realpath_lax(path).ok()) {
        if is_dir(&resolved) {
            return resolved;
        }
    }
    if is_dir(cwd) && inside_package_project(cwd, home) {
        return cwd.to_path_buf();
    }
    home.to_path_buf()
}

#[cfg(all(test, unix))]
#[path = "package_script_memory_tests.rs"]
mod tests;
