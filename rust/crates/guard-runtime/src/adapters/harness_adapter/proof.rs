//! Managed-install proofs: the digest of every Guard-written file a harness
//! manifest names, inside the managed home or Guard home, so health checks
//! and approvals can tell an intact install from a changed one.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::files::{render, text, Doc};
use super::kimi::expand_user;
use super::{path_text, Ctx, Failure, Step};
use crate::pyjson::PyVal;

pub(crate) const SCHEMA: &str = "guard.managed-install-proof.v1";
const PATH_KEYS: [&str; 8] = [
    "config_path",
    "hooks_path",
    "managed_config_path",
    "managed_hooks_path",
    "plugin_path",
    "pretool_hook_path",
    "prompt_hook_path",
    "shim_path",
];
const PATH_LIST_KEYS: [&str; 2] = ["shim_paths", "protection_artifact_paths"];
const MAX_PROOF_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// `_allowed_file`: an absolute regular file, not a link, under the home or
/// the Guard home, small enough to digest.
fn allowed_file(ctx: &Ctx, value: Option<&Value>) -> Option<PathBuf> {
    let value = value?.as_str().filter(|value| !value.trim().is_empty())?;
    let candidate = expand_user(ctx, value);
    if !candidate.is_absolute() || candidate.is_symlink() || !candidate.is_file() {
        return None;
    }
    let resolved = fs::canonicalize(&candidate).ok()?;
    if fs::metadata(&resolved).ok()?.len() > MAX_PROOF_FILE_BYTES {
        return None;
    }
    let roots = [ctx.resolved(&ctx.home), ctx.resolved(&ctx.guard_home)];
    roots
        .iter()
        .any(|root| resolved.starts_with(root))
        .then_some(resolved)
}

fn sha256(path: &Path) -> Option<String> {
    let mut source = File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut chunk).ok()?;
        if read == 0 {
            return Some(hex::encode(digest.finalize()));
        }
        digest.update(&chunk[..read]);
    }
}

/// `_manifest_paths`: every allowed file the manifest names, sorted.
fn manifest_paths(ctx: &Ctx, manifest: &Map<String, Value>) -> Vec<PathBuf> {
    let mut candidates: Vec<Option<&Value>> =
        PATH_KEYS.iter().map(|key| manifest.get(*key)).collect();
    for key in PATH_LIST_KEYS {
        if let Some(Value::Array(items)) = manifest.get(key) {
            candidates.extend(items.iter().map(Some));
        }
    }
    let mut paths: Vec<PathBuf> = candidates
        .into_iter()
        .filter_map(|candidate| allowed_file(ctx, candidate))
        .collect();
    paths.sort_by_key(|path| path_text(path));
    paths.dedup();
    paths
}

/// The `protection_artifact_proof` `bind_managed_install_proof` adds.
pub(crate) fn bind(ctx: &Ctx, manifest: &Map<String, Value>) -> Step<PyVal> {
    let artifacts = manifest_paths(ctx, manifest)
        .iter()
        .map(|path| {
            let digest = sha256(path)
                .ok_or_else(|| Failure::Os(format!("cannot read {}", path_text(path))))?;
            let mut artifact = Doc::default();
            artifact
                .set("path", text(path_text(path)))
                .set("sha256", text(digest));
            Ok(artifact.value())
        })
        .collect::<Step<Vec<_>>>()?;
    let mut proof = Doc::default();
    proof
        .set("schema_version", text(SCHEMA))
        .set("artifacts", PyVal::List(artifacts));
    Ok(proof.value())
}

/// `verify_managed_install_proof`: `None` when the manifest carries no proof.
pub(crate) fn verify(ctx: &Ctx, manifest: &Value) -> Option<bool> {
    let proof = manifest.get("protection_artifact_proof")?.as_object()?;
    if proof.get("schema_version").and_then(Value::as_str) != Some(SCHEMA) {
        return None;
    }
    let artifacts = proof
        .get("artifacts")?
        .as_array()
        .filter(|items| !items.is_empty())?;
    Some(artifacts.iter().all(|artifact| {
        let Some(artifact) = artifact.as_object() else {
            return false;
        };
        let path = allowed_file(ctx, artifact.get("path"));
        match (path, artifact.get("sha256").and_then(Value::as_str)) {
            (Some(path), Some(expected)) => sha256(&path).as_deref() == Some(expected),
            _ => false,
        }
    }))
}

pub(crate) fn dispatch(op: &str, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let manifest = fields.get("manifest").ok_or(Failure::Invalid)?;
    match op {
        "proof_verify" => Ok(json!({ "verified": verify(ctx, manifest) })),
        "proof_bind" => {
            let manifest = manifest.as_object().ok_or(Failure::Invalid)?;
            Ok(json!({ "proof": render(&bind(ctx, manifest)?)? }))
        }
        _ => Err(Failure::Invalid),
    }
}
