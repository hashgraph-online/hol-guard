//! Derive the tree installed by the pinned Python bootstrap from an outside
//! source-file hash map. The map's Git provenance must be established by its
//! caller; this data-only plan never reads a checkout or installs files.

use crate::crypto::{is_sha256, sha256};
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonical_relative_asset_path;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SOURCE_FILES: usize = 2046;
const CONTROL_PLANE_FILES: &[&str] = &[
    "__init__.py",
    "vm_worker.py",
    "vm_live.py",
    "vm_features.py",
    "feature_entry.py",
    "stage_candidate.py",
    "artifacts.py",
    "vm_build.py",
    "vm_network.py",
    "Builder.Dockerfile",
    "Builder.apparmor",
    "builder_entry.py",
    "build_artifact.py",
    "stage_outcome.py",
    "executor_image.py",
    "bootstrap_guest.py",
    "Executor.Dockerfile",
    "malloc_policy.c",
    "malloc.preload",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerInstallPlan {
    /// The expected TreeKind::Controller digest after a fresh Python install
    /// with Root ownership, mode 0755 directories and mode 0444 files.
    pub tree_digest: String,
    pub installed_files: BTreeMap<String, String>,
    pub entries: usize,
}

fn valid_source_path(path: &str) -> bool {
    (path == "ci/__init__.py" || path.starts_with("ci/gauntlet/"))
        && canonical_relative_asset_path(path)
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
}

fn selected_by_bootstrap(path: &str) -> bool {
    if path == "ci/__init__.py" {
        return true;
    }
    let components: Vec<_> = path.split('/').collect();
    !components.contains(&"__pycache__")
        && !path.ends_with(".pyc")
        && (!components.contains(&"control_plane")
            || components
                .last()
                .is_some_and(|name| CONTROL_PLANE_FILES.contains(name)))
}

/// Reproduce bootstrap.py's file selection and bootstrap_guest.py's fresh
/// directory/file modes, then hash the exact shape used by the live controller
/// tree verifier. A map of claimed hashes is not an authenticated Git tree;
/// source-byte, installer-generation and outside-pin custody remain separate.
/// No file is read, written or executed here.
pub fn plan_controller_install(
    source_hashes: &BTreeMap<String, String>,
) -> Result<ControllerInstallPlan> {
    if source_hashes.is_empty() || source_hashes.len() > MAX_SOURCE_FILES {
        return Err(EvidenceError::Invalid(
            "controller source map exceeds bounds",
        ));
    }
    let mut installed_files = BTreeMap::new();
    for (path, hash) in source_hashes {
        if !valid_source_path(path) || !is_sha256(hash) {
            return Err(EvidenceError::Invalid(
                "invalid controller source map entry",
            ));
        }
        if selected_by_bootstrap(path) {
            installed_files.insert(path.clone(), hash.clone());
        }
    }
    if installed_files.len() > MAX_SOURCE_FILES
        || [
            "ci/gauntlet/__init__.py",
            "ci/gauntlet/benchmark/__main__.py",
            "ci/gauntlet/control_plane/bootstrap_guest.py",
        ]
        .iter()
        .any(|path| !installed_files.contains_key(*path))
    {
        return Err(EvidenceError::Invalid("incomplete controller source map"));
    }
    let mut directories = BTreeSet::new();
    for path in installed_files.keys() {
        let mut prefix = String::new();
        let components: Vec<_> = path.split('/').collect();
        for component in &components[..components.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            directories.insert(prefix.clone());
        }
    }
    if directories
        .iter()
        .any(|path| installed_files.contains_key(path))
    {
        return Err(EvidenceError::Invalid(
            "controller source file conflicts with a directory",
        ));
    }
    let mut rows = Map::new();
    rows.insert(".".to_owned(), json!({"mode":0o755,"uid":0}));
    for path in &directories {
        rows.insert(path.clone(), json!({"mode":0o755,"uid":0}));
    }
    for (path, digest) in &installed_files {
        rows.insert(path.clone(), json!({"mode":0o444,"uid":0,"sha256":digest}));
    }
    let entries = directories.len() + installed_files.len();
    let tree_digest = sha256(&canonical_value(&Value::Object(rows))?);
    Ok(ControllerInstallPlan {
        tree_digest,
        installed_files,
        entries,
    })
}
