//! Source-of-truth inspection for inventory metadata, ported from
//! `guard.aibom_symlink`.
//!
//! An inventory item whose config path is a symlink records where that link
//! actually leads. Doing so means walking a chain the user did not write,
//! reading what it ends at, and emitting none of it: the item carries
//! fingerprints, a path class and a validation state, never a raw local path.
//! That is filesystem work bounded by a safe-root check, so it belongs to the
//! resident rather than to the caller assembling the snapshot.
//!
//! The fingerprints are identities a stored snapshot is compared by, so the
//! shaping below follows the Python source rather than a tidier equivalent:
//! the hop fingerprint doubles as the loop key, a relative link target is
//! resolved against the parent only when a workspace is in play, and a tree
//! fingerprint reads the whole absolute path's components when deciding which
//! files an ignored directory name excludes.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::inventory_fingerprints::{fingerprint_mapping, fingerprint_text};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::aibom_paths::{exists, is_dir, is_file, is_symlink, resolve, resolves_within_root};

/// `_MAX_SYMLINK_HOPS`: a chain longer than this is reported as a loop.
const MAX_SYMLINK_HOPS: usize = 16;
/// `_MAX_SYMLINK_TARGET_BYTES`: how much of a link target is fingerprinted.
const MAX_SYMLINK_TARGET_BYTES: usize = 1024 * 1024;
/// `_MAX_FINGERPRINT_FILE_BYTES`: how much of a tree member is fingerprinted.
const MAX_FINGERPRINT_FILE_BYTES: usize = 1024 * 1024;
/// How many files a linked directory may hold before it stops being
/// fingerprintable. The caller asks for a whole detection's artifacts under one
/// deadline, so a single tree cannot be allowed to spend it: past this the
/// target reports no hash, the way an unreadable member already does.
const MAX_TREE_FILES: usize = 20_000;
/// `_IGNORED_TREE_DIR_NAMES`.
const IGNORED_TREE_DIR_NAMES: [&str; 8] = [
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "node_modules",
];
/// The directory names `classify_path_class` reads as a harness config root.
const CONFIG_MARKERS: [&str; 7] = [
    ".config",
    ".cursor",
    ".codex",
    ".claude",
    ".gemini",
    ".openclaw",
    ".hermes",
];

/// `AibomSourceInspection`, with the redaction summary kept as its parts so
/// the caller that renders `sourceOfTruth` is the only one spelling the wire
/// shape.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AibomSourceInspection {
    pub(crate) source_fingerprint: String,
    pub(crate) path_class: &'static str,
    pub(crate) link_kind: &'static str,
    pub(crate) validation_state: &'static str,
    pub(crate) target_content_hash: Option<String>,
    pub(crate) path_fingerprint: String,
    pub(crate) hop_fingerprints: Vec<String>,
}

/// `inspect_aibom_source_path`.
pub(crate) fn inspect_aibom_source_path(
    path: &Path,
    safe_roots: &[PathBuf],
    home_dir: &Path,
    workspace_dir: Option<&Path>,
    follow_unsafe_symlinks: bool,
) -> AibomSourceInspection {
    let path_class = classify_path_class(path, home_dir, workspace_dir);
    let mut link_kind = "copy";
    let validation_state;
    let mut target_content_hash = None;
    let mut hop_fingerprints = Vec::new();

    let path_fingerprint = fingerprint_redacted_path(path, home_dir, workspace_dir);

    // A broken symlink does not exist but is still a link to inspect.
    if !exists(path) && !is_symlink(path) {
        return build_inspection(
            path_fingerprint,
            path_class,
            link_kind,
            "missing",
            None,
            hop_fingerprints,
        );
    }

    if is_symlink(path) {
        link_kind = "symlink";
        let (resolved, state, hops) = resolve_symlink_chain(
            path,
            safe_roots,
            home_dir,
            workspace_dir,
            follow_unsafe_symlinks,
        );
        validation_state = state;
        hop_fingerprints = hops;
        if let (Some(target), "valid") = (resolved, validation_state) {
            target_content_hash = content_hash_for_target(&target, home_dir);
        }
    } else if !follow_unsafe_symlinks && !is_within_safe_roots(path, safe_roots) {
        validation_state = "escape_blocked";
    } else {
        validation_state = "valid";
        target_content_hash = content_hash_for_target(path, home_dir);
    }

    build_inspection(
        path_fingerprint,
        path_class,
        link_kind,
        validation_state,
        target_content_hash,
        hop_fingerprints,
    )
}

/// `classify_path_class`.
pub(crate) fn classify_path_class(
    path: &Path,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> &'static str {
    let Some(candidate) = classified_candidate(path, home_dir, workspace_dir) else {
        return "unknown";
    };
    if let Some(workspace) = workspace_dir {
        if resolves_within_root(workspace, &candidate, false) {
            return "workspace_relative";
        }
    }
    if resolves_within_root(home_dir, &candidate, false) {
        return "home_relative";
    }
    if candidate
        .components()
        .any(|component| CONFIG_MARKERS.contains(&component.as_os_str().to_string_lossy().as_ref()))
    {
        return "config_root";
    }
    let text = posix_text(&candidate);
    if text.contains("/mnt/") || text.starts_with("/var/") {
        return "container_mount";
    }
    "unknown"
}

/// The path `classify_path_class` classifies: a link's target, resolved
/// against the parent when a workspace is in play and against the home
/// directory otherwise, or the resolved path itself.
fn classified_candidate(
    path: &Path,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> Option<PathBuf> {
    if !is_symlink(path) {
        return resolve(path).ok();
    }
    let target = fs::read_link(path).ok()?;
    if target.is_absolute() {
        return resolve(&target).ok();
    }
    let base = if workspace_dir.is_some() {
        path.parent().unwrap_or(Path::new("")).join(&target)
    } else {
        home_dir.join(&target)
    };
    resolve(&base).ok()
}

/// `fingerprint_redacted_path`.
///
/// A link and the file it leads to have to fingerprint differently, or the hop
/// list reads as a cycle the moment the first hop is taken. So a symlink keeps
/// its own name and only its parent is resolved; everything else resolves
/// whole. The chosen path is then redacted as it stands, never resolved again.
pub(crate) fn fingerprint_redacted_path(
    path: &Path,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> String {
    let candidate = if is_symlink(path) {
        link_in_its_resolved_parent(path)
    } else {
        resolve(path).unwrap_or_else(|_| path.to_path_buf())
    };
    if let Some(workspace) = workspace_dir {
        if let Ok(root) = resolve(workspace) {
            if let Ok(relative) = candidate.strip_prefix(&root) {
                return fingerprint_text(&format!("{{workspace}}/{}", relative_posix(relative)));
            }
        }
    }
    fingerprint_text(&redact_resolved_path(&candidate, home_dir))
}

/// The link's own place: its parent resolved, its own name left alone.
fn link_in_its_resolved_parent(path: &Path) -> PathBuf {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return path.to_path_buf();
    };
    match resolve(parent) {
        Ok(resolved) => resolved.join(name),
        Err(_) => path.to_path_buf(),
    }
}

/// `redact_local_path(path, home_dir=home_dir)` over a path already resolved as
/// far as it should be: the home-relative spelling, or the bare file name when
/// the path lies outside the home directory.
fn redact_resolved_path(candidate: &Path, home_dir: &Path) -> String {
    let file_name = || {
        candidate
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let Ok(home) = resolve(home_dir) else {
        return file_name();
    };
    match candidate.strip_prefix(&home) {
        Ok(relative) => format!("{{home}}/{}", relative_posix(relative)),
        Err(_) => file_name(),
    }
}

/// `_build_inspection`.
fn build_inspection(
    path_fingerprint: String,
    path_class: &'static str,
    link_kind: &'static str,
    validation_state: &'static str,
    target_content_hash: Option<String>,
    hop_fingerprints: Vec<String>,
) -> AibomSourceInspection {
    let source_fingerprint = fingerprint_mapping(&json!({
        "path": path_fingerprint,
        "link_kind": link_kind,
        "path_class": path_class,
        "validation_state": validation_state,
        "target_content_hash": target_content_hash,
        "hop_count": hop_fingerprints.len(),
    }));
    AibomSourceInspection {
        source_fingerprint,
        path_class,
        link_kind,
        validation_state,
        target_content_hash,
        path_fingerprint,
        hop_fingerprints,
    }
}

/// `_resolve_symlink_chain`.
fn resolve_symlink_chain(
    path: &Path,
    safe_roots: &[PathBuf],
    home_dir: &Path,
    workspace_dir: Option<&Path>,
    follow_unsafe_symlinks: bool,
) -> (Option<PathBuf>, &'static str, Vec<String>) {
    let mut hop_fingerprints: Vec<String> = Vec::new();
    let mut current = path.to_path_buf();

    for _ in 0..MAX_SYMLINK_HOPS {
        let hop = fingerprint_redacted_path(&current, home_dir, workspace_dir);
        // The fingerprint is the loop key: two hops that redact the same way
        // are the same place as far as the recorded evidence is concerned.
        if hop_fingerprints.contains(&hop) {
            hop_fingerprints.push(hop);
            return (None, "loop", hop_fingerprints);
        }
        hop_fingerprints.push(hop);

        if !is_symlink(&current) {
            if !exists(&current) {
                return (None, "broken", hop_fingerprints);
            }
            if !follow_unsafe_symlinks && !is_within_safe_roots(&current, safe_roots) {
                return (None, "escape_blocked", hop_fingerprints);
            }
            return (Some(current), "valid", hop_fingerprints);
        }

        let Ok(target) = fs::read_link(&current) else {
            return (None, "broken", hop_fingerprints);
        };
        let next = if target.is_absolute() {
            target
        } else {
            current.parent().unwrap_or(Path::new("")).join(target)
        };
        // A resolve that cannot answer is a chain that does not end, which the
        // Python source reaches as `RuntimeError` or `ELOOP`.
        let Ok(resolved) = resolve(&next) else {
            return (None, "loop", hop_fingerprints);
        };
        current = resolved;
    }

    (None, "loop", hop_fingerprints)
}

/// `_is_within_safe_roots`.
fn is_within_safe_roots(path: &Path, safe_roots: &[PathBuf]) -> bool {
    safe_roots
        .iter()
        .any(|root| resolves_within_root(root, path, false))
}

/// `source_of_truth_metadata_from_inspection`.
pub(crate) fn source_of_truth_metadata_from_inspection(
    inspection: &AibomSourceInspection,
    source_link_id: &str,
) -> Value {
    json!({
        "sourceLinkId": source_link_id,
        "sourceFingerprint": inspection.source_fingerprint,
        "linkKind": inspection.link_kind,
        "validationState": inspection.validation_state,
        "pathClass": inspection.path_class,
        "redactionSummary": {
            "rawPathsIncluded": false,
            "hopFingerprints": inspection.hop_fingerprints,
            "pathFingerprint": inspection.path_fingerprint,
        },
        "metadata": {
            "targetContentHash": inspection.target_content_hash,
        },
    })
}

/// `path_has_symlink_component`: whether any component from the allowed root
/// down to the path itself is a link. A path outside the root counts as one,
/// because the root cannot vouch for a walk that never entered it.
pub(crate) fn path_has_symlink_component(path: &Path, allowed_root: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(allowed_root) else {
        return true;
    };
    if is_symlink(allowed_root) {
        return true;
    }
    let mut current = allowed_root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if is_symlink(&current) {
            return true;
        }
    }
    false
}

/// `_content_hash_for_target`.
fn content_hash_for_target(path: &Path, home_dir: &Path) -> Option<String> {
    if is_dir(path) {
        return fingerprint_path_tree(path, home_dir);
    }
    if is_file(path) {
        let payload = read_bounded_file_bytes(path, MAX_SYMLINK_TARGET_BYTES)?;
        return Some(fingerprint_text(&String::from_utf8_lossy(&payload)));
    }
    None
}

/// `fingerprint_path_tree`: every readable file under the root, by its
/// redacted path and its bounded digest. A file that cannot be read makes the
/// whole tree unfingerprintable, as the `OSError` does in the Python source.
fn fingerprint_path_tree(root: &Path, home_dir: &Path) -> Option<String> {
    let paths = if is_file(root) {
        vec![root.to_path_buf()]
    } else {
        let mut collected = Vec::new();
        let mut visited = 0_usize;
        collect_tree_files(root, &mut collected, &mut visited);
        if visited > MAX_TREE_FILES {
            return None;
        }
        // `sorted()` over `Path` objects compares them component by component,
        // so `foo/bar.md` precedes `foo.md`. Comparing the whole path string
        // would reverse that pair and change the fingerprint of a tree nothing
        // had touched.
        collected.sort_by_cached_key(|path| {
            path.components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        });
        collected
    };
    let mut entries = Vec::with_capacity(paths.len());
    for path in &paths {
        entries.push(json!({
            "path": redact_resolved_path(&resolve(path).unwrap_or_else(|_| path.clone()), home_dir),
            "sha256": fingerprint_file_bytes(path)?,
        }));
    }
    Some(fingerprint_mapping(&Value::Array(entries)))
}

/// `root.rglob("*")` filtered as the Python source filters it: files only,
/// never `.env`, and nothing whose absolute path names an ignored directory.
/// A directory symlink is not descended into, matching `pathlib`.
///
/// `visited` counts every entry the walk looks at, directories included, and
/// the walk stops once it passes `MAX_TREE_FILES` so the caller can tell a
/// bounded tree from one it only half read.
fn collect_tree_files(directory: &Path, collected: &mut Vec<PathBuf>, visited: &mut usize) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if *visited > MAX_TREE_FILES {
            return;
        }
        *visited += 1;
        let path = entry.path();
        if is_dir(&path) && !is_symlink(&path) {
            collect_tree_files(&path, collected, visited);
            continue;
        }
        if !is_file(&path) {
            continue;
        }
        if path.file_name().is_some_and(|name| name == ".env") {
            continue;
        }
        if path.components().any(|component| {
            IGNORED_TREE_DIR_NAMES.contains(&component.as_os_str().to_string_lossy().as_ref())
        }) {
            continue;
        }
        collected.push(path);
    }
}

/// `_fingerprint_file_bytes`.
fn fingerprint_file_bytes(path: &Path) -> Option<String> {
    let payload = read_bounded_file_bytes(path, MAX_FINGERPRINT_FILE_BYTES)?;
    Some(hex::encode(Sha256::digest(&payload)))
}

/// `_read_bounded_file_bytes`.
fn read_bounded_file_bytes(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
    let mut file = fs::File::open(path).ok()?;
    let mut collected = Vec::new();
    let mut remaining = max_bytes;
    let mut chunk = [0_u8; 65_536];
    while remaining > 0 {
        let wanted = remaining.min(chunk.len());
        match file.read(&mut chunk[..wanted]) {
            Ok(0) => break,
            Ok(count) => {
                collected.extend_from_slice(&chunk[..count]);
                remaining -= count;
            }
            Err(_) => return None,
        }
    }
    Some(collected)
}

/// `relative.as_posix()`, where an empty relative path is `.` as `pathlib`
/// spells it.
fn relative_posix(relative: &Path) -> String {
    let parts: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.is_empty() {
        return ".".to_owned();
    }
    parts.join("/")
}

/// `path.as_posix()`.
fn posix_text(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        return text.replace('\\', "/");
    }
    text
}

#[cfg(test)]
#[path = "aibom_symlink_tests.rs"]
mod tests;
