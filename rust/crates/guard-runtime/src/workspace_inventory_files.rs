//! Workspace file discovery and guarded text reads for the workspace
//! inventory op: the bounded manifest/lockfile walk, the candidate fallback,
//! the sensitive-basename filter and Python-compatible text decoding.

use std::fs;
use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::is_audit_sensitive_basename;
use guard_command::package_intent_common::{
    existing_relative_paths, resolve_path_within_workspace,
};

pub(crate) const MANIFEST_CANDIDATES: [&str; 12] = [
    "package.json",
    "requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
];
pub(crate) const LOCKFILE_CANDIDATES: [&str; 13] = [
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "gradle.lockfile",
    "composer.lock",
    "Gemfile.lock",
];
const SKIP_DIRS: [&str; 15] = [
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".next",
    "target",
    ".guard",
    ".worktrees",
    "worktrees",
];
const MAX_DEPTH: usize = 3;
pub(crate) const MAX_SBOM_BYTES: u64 = 10 * 1024 * 1024;

pub(crate) fn expanduser(path: &str) -> PathBuf {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let home = PathBuf::from(home);
            return if path == "~" {
                home
            } else {
                home.join(&path[2..])
            };
        }
    }
    PathBuf::from(path)
}

pub(crate) fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `Path.read_text(encoding="utf-8")`: strict UTF-8 with universal newlines.
pub(crate) fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    if !text.contains('\r') {
        return Some(text);
    }
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `_read_workspace_audit_text`.
pub(crate) fn read_workspace_audit_text(workspace: &Path, relative_path: &str) -> Option<String> {
    if is_audit_sensitive_basename(basename(relative_path)) {
        return None;
    }
    let resolved = resolve_path_within_workspace(workspace, relative_path)?;
    if !resolved.is_file() {
        return None;
    }
    read_text(&resolved)
}

fn is_directory(entry: &fs::DirEntry) -> bool {
    match entry.file_type() {
        Ok(kind) if kind.is_symlink() => fs::metadata(entry.path()).is_ok_and(|meta| meta.is_dir()),
        Ok(kind) => kind.is_dir(),
        Err(_) => false,
    }
}

fn walk(
    directory: &Path,
    relative: &str,
    depth: usize,
    manifests: &mut Vec<String>,
    lockfiles: &mut Vec<String>,
) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut files: Vec<String> = Vec::new();
    let mut subdirectories: Vec<(String, bool)> = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_directory(&entry) {
            let linked = entry.file_type().is_ok_and(|kind| kind.is_symlink());
            subdirectories.push((name, linked));
        } else {
            files.push(name);
        }
    }
    // Readdir order is filesystem specific; every directory is visited by name.
    files.sort();
    subdirectories.sort();
    for name in files {
        let path = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if MANIFEST_CANDIDATES.contains(&name.as_str()) {
            if !manifests.contains(&path) {
                manifests.push(path);
            }
        } else if LOCKFILE_CANDIDATES.contains(&name.as_str()) && !lockfiles.contains(&path) {
            lockfiles.push(path);
        }
    }
    if depth >= MAX_DEPTH {
        return;
    }
    for (name, linked) in subdirectories {
        if linked || SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        let child = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        walk(
            &directory.join(&name),
            &child,
            depth + 1,
            manifests,
            lockfiles,
        );
    }
}

/// `_workspace_files`: the bounded walk, else the root candidates.
pub(crate) fn workspace_files(workspace_dir: &str) -> (Vec<String>, Vec<String>) {
    let workspace = expanduser(workspace_dir);
    let Ok(root) = fs::canonicalize(&workspace) else {
        return (Vec::new(), Vec::new());
    };
    let mut manifests = Vec::new();
    let mut lockfiles = Vec::new();
    walk(&root, "", 0, &mut manifests, &mut lockfiles);
    if !manifests.is_empty() || !lockfiles.is_empty() {
        return (manifests, lockfiles);
    }
    let manifest_candidates: Vec<String> = MANIFEST_CANDIDATES.map(String::from).to_vec();
    let lockfile_candidates: Vec<String> = LOCKFILE_CANDIDATES.map(String::from).to_vec();
    (
        existing_relative_paths(Some(&root), &manifest_candidates),
        existing_relative_paths(Some(&root), &lockfile_candidates),
    )
}

/// `_resolve_sbom_paths`: existing SBOM files, relative to the workspace when
/// they sit inside it and by basename otherwise.
pub(crate) fn resolve_sbom_paths(workspace_dir: &str, sbom_paths: &[String]) -> Vec<String> {
    let workspace = Path::new(workspace_dir);
    let mut resolved: Vec<String> = Vec::new();
    for raw in sbom_paths {
        let candidate = Path::new(raw);
        let disk_path = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            workspace.join(candidate)
        };
        if !disk_path.exists() {
            continue;
        }
        let normalized = match disk_path.strip_prefix(workspace) {
            Ok(relative) => {
                let joined = relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                if joined.is_empty() {
                    ".".to_owned()
                } else {
                    joined
                }
            }
            Err(_) => disk_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        if !resolved.contains(&normalized) {
            resolved.push(normalized);
        }
    }
    resolved
}

/// `_read_sbom_text`: bounded, strict UTF-8, `None` on any failure.
pub(crate) fn read_sbom_text(disk_path: &Path) -> Option<String> {
    if fs::metadata(disk_path).ok()?.len() > MAX_SBOM_BYTES {
        return None;
    }
    read_text(disk_path)
}
