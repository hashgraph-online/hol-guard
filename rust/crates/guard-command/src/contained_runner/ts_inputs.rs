//! Bounded, hash-bound inputs for contained explicit-source TypeScript checks.
//!
//! Faithful port of `runtime/typescript_snapshot_inputs.py`.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::common::{file_sha256, framed_digest, normpath};
use super::contract::Input;
use super::snapshot::Budget;

const MAX_TREE_FILES: usize = 10_000;
const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const PROTECTED_NAMES: &[&str] = &[
    ".git",
    ".ssh",
    ".aws",
    ".gnupg",
    ".guard",
    "credentials",
    "credentials.json",
    "secrets.json",
];
const INPUT_SUFFIXES: &[&str] = &[".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];

/// Exact compiler tree and workspace-closure digests plus their inputs.
pub(crate) struct TypescriptInputs {
    pub(crate) tree_digest: String,
    pub(crate) package_inputs: Vec<Input>,
    pub(crate) closure_digest: String,
    pub(crate) closure_inputs: Vec<Input>,
}

pub(crate) fn typescript_snapshot_inputs(
    workspace: &Path,
    package_root: &Path,
    sources: &[String],
) -> Result<TypescriptInputs, String> {
    let (tree_digest, package_inputs) = tree_inputs(workspace, package_root)?;
    let (closure_digest, closure_inputs) = closure_inputs(workspace, package_root, sources)?;
    Ok(TypescriptInputs {
        tree_digest,
        package_inputs,
        closure_digest,
        closure_inputs,
    })
}

fn parts(relative: &Path) -> Vec<String> {
    relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect()
}

fn posix(relative: &Path) -> String {
    parts(relative).join("/")
}

fn entries(directory: &Path, budget: &mut Budget) -> Result<Vec<(PathBuf, fs::FileType)>, String> {
    let failed = || "containment input discovery failed".to_owned();
    let mut found = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| failed())? {
        let entry = entry.map_err(|_| failed())?;
        budget.visited += 1;
        budget.check(
            "containment discovery entry budget exceeded",
            "containment discovery time budget exceeded",
        )?;
        let file_type = entry.file_type().map_err(|_| failed())?;
        found.push((entry.path(), file_type));
    }
    Ok(found)
}

fn budget_check(budget: &Budget) -> Result<(), String> {
    budget.check(
        "containment discovery entry budget exceeded",
        "containment discovery time budget exceeded",
    )
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    let is_symlink = fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
    if is_symlink || !path.is_dir() {
        return Err("package tree must be an existing canonical directory".to_owned());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| "package tree must be an existing canonical directory".to_owned())?;
    if canonical.to_string_lossy() != normpath(&path.to_string_lossy()) {
        return Err("package tree cannot contain aliases".to_owned());
    }
    Ok(canonical)
}

fn tree_inputs(workspace: &Path, root: &Path) -> Result<(String, Vec<Input>), String> {
    let canonical_root = canonical_directory(root)?;
    let mut captured: Vec<(String, String, Input)> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut budget = Budget::new();
    let mut directories = vec![canonical_root.clone()];
    while let Some(directory) = directories.pop() {
        for (path, file_type) in entries(&directory, &mut budget)? {
            let relative = path
                .strip_prefix(&canonical_root)
                .map_err(|_| "containment input discovery failed".to_owned())?;
            if is_protected_path(relative) {
                return Err("protected package-tree path".to_owned());
            }
            if file_type.is_symlink() {
                return Err("package tree cannot contain symlinks".to_owned());
            }
            if file_type.is_dir() {
                directories.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err("package tree inputs must be regular files".to_owned());
            }
            total_bytes += fs::symlink_metadata(&path)
                .map_err(|error| error.to_string())?
                .size();
            if captured.len() >= MAX_TREE_FILES || total_bytes > MAX_TREE_BYTES {
                return Err("package tree exceeds containment identity budget".to_owned());
            }
            let digest = file_sha256(&path)?;
            budget_check(&budget)?;
            let snapshot_path = posix(
                path.strip_prefix(workspace)
                    .map_err(|_| "containment input discovery failed".to_owned())?,
            );
            let input = Input::new(&path.to_string_lossy(), &snapshot_path, &digest)?;
            captured.push((posix(relative), digest, input));
        }
    }
    if captured.is_empty() {
        return Err("package tree is empty".to_owned());
    }
    captured.sort_by(|left, right| left.0.cmp(&right.0));
    let records: Vec<Value> = captured
        .iter()
        .map(|(relative, digest, _)| json!([relative, digest]))
        .collect();
    let digest = framed_digest(&json!({"files": records}))?;
    Ok((
        digest,
        captured.into_iter().map(|(_, _, input)| input).collect(),
    ))
}

fn closure_inputs(
    workspace: &Path,
    package_root: &Path,
    sources: &[String],
) -> Result<(String, Vec<Input>), String> {
    reject_external_node_modules(workspace)?;
    let source_paths = validated_source_paths(workspace, sources)?;
    let mut captured: Vec<(String, String, Input)> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut budget = Budget::new();
    let mut directories = vec![workspace.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for (path, file_type) in entries(&directory, &mut budget)? {
            let relative = path
                .strip_prefix(workspace)
                .map_err(|_| "containment input discovery failed".to_owned())?;
            let is_bin_dir =
                file_type.is_dir() && path.file_name().is_some_and(|name| name == ".bin");
            if path == package_root || is_bin_dir {
                continue;
            }
            if is_protected_path(relative) {
                if protected_requires_review(relative) {
                    return Err("protected TypeScript dependency cannot be omitted".to_owned());
                }
                continue;
            }
            if file_type.is_symlink() {
                return Err("TypeScript closure cannot contain symlinks".to_owned());
            }
            if file_type.is_dir() {
                directories.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err("TypeScript closure inputs must be regular files".to_owned());
            }
            if !is_typescript_input(relative) {
                continue;
            }
            let canonical = fs::canonicalize(&path).map_err(|error| error.to_string())?;
            total_bytes += fs::symlink_metadata(&path)
                .map_err(|error| error.to_string())?
                .size();
            if captured.len() >= MAX_TREE_FILES || total_bytes > MAX_SOURCE_BYTES {
                return Err("TypeScript closure exceeds containment identity budget".to_owned());
            }
            let digest = file_sha256(&canonical)?;
            budget_check(&budget)?;
            let snapshot_path = posix(relative);
            let input = Input::new(&canonical.to_string_lossy(), &snapshot_path, &digest)?;
            captured.push((snapshot_path, digest, input));
        }
    }
    captured.sort_by(|left, right| left.0.cmp(&right.0));
    let omitted = source_paths.iter().any(|path| {
        path.strip_prefix(workspace)
            .map(posix)
            .map_or(true, |relative| {
                !captured.iter().any(|item| item.0 == relative)
            })
    });
    if omitted {
        return Err("TypeScript closure omitted an explicit source".to_owned());
    }
    let records: Vec<Value> = captured
        .iter()
        .map(|(path, digest, _)| json!([path, digest]))
        .collect();
    let digest = framed_digest(&json!({"files": records}))?;
    Ok((
        digest,
        captured.into_iter().map(|(_, _, input)| input).collect(),
    ))
}

fn validated_source_paths(workspace: &Path, sources: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut canonical_sources: Vec<PathBuf> = Vec::new();
    for raw_source in sources {
        let candidate = workspace.join(raw_source);
        let is_symlink =
            fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.file_type().is_symlink());
        if is_symlink || !candidate.is_file() {
            return Err("source must be a regular non-symlinked file".to_owned());
        }
        let canonical = fs::canonicalize(&candidate).map_err(|error| error.to_string())?;
        let relative = canonical
            .strip_prefix(workspace)
            .map_err(|_| "source escaped workspace".to_owned())?;
        if is_protected_path(relative) || parts(relative).iter().any(|part| part == ".bin") {
            return Err("protected source path".to_owned());
        }
        canonical_sources.push(canonical);
    }
    let mut unique = canonical_sources.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != canonical_sources.len() {
        return Err("source closure cannot contain aliases".to_owned());
    }
    Ok(canonical_sources)
}

fn reject_external_node_modules(workspace: &Path) -> Result<(), String> {
    for ancestor in workspace.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor.join("node_modules")) {
            Ok(_) => return Err("external TypeScript dependencies require Guard review".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err("external TypeScript dependency identity is unavailable".to_owned());
            }
        }
    }
    Ok(())
}

fn is_protected_path(relative: &Path) -> bool {
    parts(relative).iter().any(|part| {
        let lowered = part.to_lowercase();
        PROTECTED_NAMES.contains(&lowered.as_str()) || lowered.starts_with(".env")
    })
}

fn protected_requires_review(relative: &Path) -> bool {
    parts(relative)
        .iter()
        .any(|part| part.to_lowercase() == "node_modules")
        || is_typescript_input(relative)
}

/// `Path.suffix`: the final dot suffix, empty for dotfiles and trailing dots.
fn suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 && index + 1 < name.len() => &name[index..],
        _ => "",
    }
}

fn is_typescript_input(relative: &Path) -> bool {
    let name = relative
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    name == "package.json" || INPUT_SUFFIXES.contains(&suffix(&name).to_lowercase().as_str())
}
