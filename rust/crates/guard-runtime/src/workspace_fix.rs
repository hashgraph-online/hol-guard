//! `workspace-fix --stdin`: the deterministic half of reviewed dependency
//! fixes.
//!
//! `plan` reads the `package.json` files the workspace inventory knows about,
//! never following a symlink, and returns one minimal version-spec edit with
//! its diff and the SHA-256 of the manifest before and after, or a reason the
//! manifest cannot take one. `apply` re-checks that the reviewed manifest is
//! unchanged and replaces it only if it still is; see `workspace_fix_fs` for
//! how the replacement fails closed. Nothing here runs a package manager or
//! any project code, and lockfiles are only listed, never written.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::workspace_fix_diff::unified_diff;
use crate::workspace_fix_fs::{
    lockfiles_for, read_manifest, replace_if_unchanged, sha256_hex, Code, Replaced, MANIFEST_NAME,
};
use crate::workspace_fix_manifest::{apply_edits, plan_edits, FixEdit};
use crate::workspace_inventory_files::workspace_files;

pub(crate) const COMMAND: &str = "workspace-fix";
pub(crate) const FEATURE: &str = "workspace-fix-v1";

const MAX_MANIFESTS: usize = 200;
const DEFAULT_MAX_PROPOSALS: usize = 20;
const HARD_MAX_PROPOSALS: usize = 200;
const DEFAULT_MAX_DIFF_BYTES: usize = 65_536;
const HARD_MAX_DIFF_BYTES: usize = 1024 * 1024;
/// Errors that say the file, not the dependency, was the problem. A manifest
/// that declares the package for real explains a refusal better, so these
/// rank last.
const FILE_REASONS: [&str; 11] = [
    "manifest_invalid_json",
    "manifest_too_deep",
    "manifest_not_utf8",
    "manifest_path_invalid",
    "manifest_missing",
    "manifest_unreadable",
    "manifest_is_symlink",
    "manifest_not_regular",
    "manifest_too_large",
    "manifest_changed",
    "manifest_root_unavailable",
];

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Plan(PlanRequest),
    Apply(ApplyRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    root: String,
    package: String,
    fix_version: String,
    #[serde(default)]
    max_proposals: usize,
    #[serde(default)]
    max_diff_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    root: String,
    manifest_path: String,
    base_sha256: String,
    new_sha256: String,
    edits: Vec<FixEdit>,
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| "workspace_fix_request_invalid".to_owned())?;
    let outcome = match request {
        Request::Plan(request) => plan(&request),
        Request::Apply(request) => apply(&request),
    };
    Ok(match outcome {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

fn bounded(value: usize, default: usize, hard: usize) -> usize {
    if value == 0 {
        default
    } else {
        value.min(hard)
    }
}

fn canonical_root(root: &str) -> Result<PathBuf, Code> {
    let requested = PathBuf::from(root);
    if !requested.is_absolute() {
        return Err("workspace_fix_root_not_absolute");
    }
    let canonical = fs::canonicalize(&requested).map_err(|_| "workspace_fix_root_missing")?;
    if !fs::metadata(&canonical).is_ok_and(|meta| meta.is_dir()) {
        return Err("workspace_fix_root_not_directory");
    }
    Ok(canonical)
}

/// `package.json` files in the inventory the assessment itself reads, so a fix
/// can only target a manifest the assessment could have reported on.
fn inventory_manifests(root: &Path) -> Result<Vec<String>, Code> {
    let text = root.to_str().ok_or("workspace_fix_root_not_utf8")?;
    let (manifests, _) = workspace_files(text);
    let mut paths: Vec<String> = manifests
        .into_iter()
        .filter(|path| path.rsplit('/').next() == Some(MANIFEST_NAME))
        .collect();
    // Shallow manifests first, so the scan limit drops the deepest ones.
    paths.sort_by(|left, right| {
        let depth = |path: &str| path.matches('/').count();
        depth(left).cmp(&depth(right)).then_with(|| left.cmp(right))
    });
    paths.dedup();
    Ok(paths)
}

struct Planned {
    manifest_path: String,
    base_sha256: String,
    new_sha256: String,
    edits: Vec<FixEdit>,
    diff: String,
}

fn plan_manifest(
    root: &Path,
    relative: &str,
    package: &str,
    fix_version: &str,
    max_diff_bytes: usize,
) -> Result<Planned, Code> {
    let manifest = read_manifest(root, relative)?;
    let text = std::str::from_utf8(&manifest.bytes).map_err(|_| "manifest_not_utf8")?;
    let edits = plan_edits(text, package, fix_version)?;
    let updated = apply_edits(text, &edits)?;
    let diff = unified_diff(text, &updated, relative);
    if diff.len() > max_diff_bytes {
        return Err("diff_too_large");
    }
    Ok(Planned {
        manifest_path: relative.to_owned(),
        base_sha256: sha256_hex(&manifest.bytes),
        new_sha256: sha256_hex(updated.as_bytes()),
        edits,
        diff,
    })
}

fn plan(request: &PlanRequest) -> Result<Value, String> {
    let root = canonical_root(&request.root).map_err(str::to_owned)?;
    let max_proposals = bounded(
        request.max_proposals,
        DEFAULT_MAX_PROPOSALS,
        HARD_MAX_PROPOSALS,
    );
    let max_diff_bytes = bounded(
        request.max_diff_bytes,
        DEFAULT_MAX_DIFF_BYTES,
        HARD_MAX_DIFF_BYTES,
    );
    let mut manifests = inventory_manifests(&root).map_err(str::to_owned)?;
    let truncated = manifests.len() > MAX_MANIFESTS;
    manifests.truncate(MAX_MANIFESTS);
    let mut planned: Vec<Planned> = Vec::new();
    let mut declared: Vec<(String, Code)> = Vec::new();
    let mut other: Vec<(String, Code)> = Vec::new();
    for relative in manifests {
        match plan_manifest(
            &root,
            &relative,
            &request.package,
            &request.fix_version,
            max_diff_bytes,
        ) {
            Ok(item) => planned.push(item),
            Err("not_declared") => {}
            Err(code) if FILE_REASONS.contains(&code) => other.push((relative, code)),
            Err(code) => declared.push((relative, code)),
        }
    }
    let mut skipped = declared;
    skipped.extend(other);
    let overflow = planned.split_off(planned.len().min(max_proposals));
    skipped.extend(
        overflow
            .into_iter()
            .map(|item| (item.manifest_path, "too_many_manifests")),
    );
    Ok(json!({
        "proposals": planned.iter().map(|item| json!({
            "manifest_path": item.manifest_path,
            "base_sha256": item.base_sha256,
            "new_sha256": item.new_sha256,
            "edits": item.edits,
            "diff": item.diff,
        })).collect::<Vec<_>>(),
        "skipped": skipped.iter().map(|(path, reason)| json!({
            "manifest_path": path,
            "reason": reason,
        })).collect::<Vec<_>>(),
        "truncated": truncated,
    }))
}

fn stale(reason: &str, preserved: Option<String>) -> Value {
    json!({"status": "stale", "reason": reason, "preserved_path": preserved})
}

fn apply(request: &ApplyRequest) -> Result<Value, String> {
    let root = canonical_root(&request.root).map_err(str::to_owned)?;
    let relative = request.manifest_path.as_str();
    let current = match read_manifest(&root, relative) {
        Ok(current) => current,
        Err(reason) if reason == "manifest_path_invalid" => return Err(reason.to_owned()),
        Err(reason) => return Ok(stale(reason, None)),
    };
    if sha256_hex(&current.bytes) != request.base_sha256 {
        return Ok(stale("manifest_changed", None));
    }
    let updated = match std::str::from_utf8(&current.bytes)
        .map_err(|_| "manifest_not_utf8")
        .and_then(|text| apply_edits(text, &request.edits))
    {
        Ok(updated) => updated,
        Err(reason) => return Ok(stale(reason, None)),
    };
    if sha256_hex(updated.as_bytes()) != request.new_sha256 {
        return Ok(stale("proposal_mismatch", None));
    }
    match replace_if_unchanged(&root, relative, &request.base_sha256, updated.as_bytes()) {
        Ok(Replaced::Applied) => Ok(json!({
            "status": "applied",
            "lockfiles": lockfiles_for(&root, relative),
        })),
        Ok(Replaced::Stale { reason, preserved }) => Ok(stale(reason, preserved)),
        Err(reason) => Err(reason.to_owned()),
    }
}

#[cfg(test)]
#[path = "workspace_fix_tests.rs"]
mod tests;
