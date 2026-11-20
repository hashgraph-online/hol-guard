//! Build and sign the manifest that authenticates Guard's Codex hooks.
//!
//! Ported from `build_authenticated_hook_manifest`, `describe_regular_file`,
//! `describe_executable_file` and the bridge compatibility helpers. The
//! caller names the files and commands of one installation; this module
//! reads every file through one handle, records its identity, carries the
//! previous manifest's bridge generations forward, and signs the result with
//! the Codex hook key the runtime holds.
//!
//! One fact stays with the asking interpreter: which directories are its own
//! package roots. A group-writable file under one of them may still be
//! trusted when its group is private to its owner, so the roots arrive in the
//! request.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use serde_json::{json, Map, Value};

use crate::codex_hook_bridge_trust_files::{canonical, current_uid, executable};
use crate::codex_hook_file_identity_op::sha256_file;
use crate::codex_hook_file_integrity_op::admit;

const SCHEMA_VERSION: i64 = 2;
const PURPOSE: &str = "codex-managed-hook-manifest";
const ALGORITHM: &str = "hmac-sha256";
const MAX_GENERATIONS: usize = 8;
const BRIDGE_COMMAND: &str = "codex-hook-bridge";
const TRANSPORT_ROLES: [&str; 4] = ["bridge", "launch_runtime", "runtime_trust", "windows_job"];
const LEGACY_FIELDS: [&str; 3] = [
    "authentication",
    "retained_bridge_generations",
    "compatible_bridge_argv_sha256",
];

/// The signing key the caller resolved, read by the runtime.
pub(crate) struct Signer<'a> {
    pub(crate) key: &'a [u8],
    pub(crate) key_id: &'a str,
    pub(crate) installation_id: &'a str,
}

/// The `manifest_build` answer: the signed manifest, or the refusal.
pub(crate) fn answer(
    spec: &Map<String, Value>,
    previous: Option<&Map<String, Value>>,
    package_roots: &[String],
    key: &[u8],
    (key_id, installation_id): (&str, &str),
) -> Value {
    let signer = Signer {
        key,
        key_id,
        installation_id,
    };
    match build(spec, previous, package_roots, &signer) {
        Ok(manifest) => json!({"manifest": manifest}),
        Err(reason) => json!({"error": reason}),
    }
}

/// The signed manifest for `spec`, or the reason it cannot be built.
pub(crate) fn build(
    spec: &Map<String, Value>,
    previous: Option<&Map<String, Value>>,
    package_roots: &[String],
    signer: &Signer<'_>,
) -> Result<Value, String> {
    let invalid = || "codex_hook_manifest_spec_invalid".to_owned();
    let text = |name: &str| spec.get(name).and_then(Value::as_str).ok_or_else(invalid);
    let argv = |name: &str| strings(spec.get(name)).ok_or_else(invalid);
    let roots: Vec<PathBuf> = package_roots.iter().map(PathBuf::from).collect();
    let interpreter =
        describe_executable(Path::new(text("interpreter_path")?), "interpreter", &roots)?;
    let pairs = spec
        .get("packaged_file_paths")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut packaged = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let (Some(role), Some(path)) = (
            pair.get(0).and_then(Value::as_str),
            pair.get(1).and_then(Value::as_str),
        ) else {
            return Err(invalid());
        };
        packaged.push(describe_regular(Path::new(path), role, false, &roots)?);
    }
    let mut by_role = Map::new();
    for identity in &packaged {
        if let Some(role) = identity.get("role").and_then(Value::as_str) {
            by_role.insert(role.to_owned(), identity.clone());
        }
    }
    let mut transport = Map::new();
    for role in TRANSPORT_ROLES {
        let identity = by_role.get(role).filter(|value| value.is_object());
        let Some(identity) = identity else {
            return Err("codex_hook_manifest_packaged_files_invalid".to_owned());
        };
        transport.insert(role.to_owned(), identity.clone());
    }
    if by_role.len() != pairs.len() {
        return Err("codex_hook_manifest_packaged_files_invalid".to_owned());
    }
    transport.insert("wrapper".to_owned(), Value::Null);
    let events = spec
        .get("event_bindings")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let generated_at = now_iso();
    let unsigned = json!({
        "config": {"scope": "global", "target": spelled(Path::new(text("config_path")?))},
        "compatible_bridge_argv_sha256": compatible_hashes(previous),
        "retained_bridge_generations": retained_generations(previous),
        "context": {
            "guard_home": spelled(Path::new(text("guard_home")?)),
            "home_dir": spelled(Path::new(text("home_dir")?)),
            "runtime_guard_home": spelled(Path::new(text("runtime_guard_home")?)),
            "workspace_dir": match spec.get("workspace_dir") {
                Some(Value::String(path)) => Value::String(spelled(Path::new(path))),
                Some(Value::Null) | None => Value::Null,
                Some(_) => return Err(invalid()),
            },
        },
        "daemon_start": {
            "argv": argv("daemon_start_argv")?,
            "interpreter": interpreter,
            "package_roles": ["daemon_entrypoint", "daemon_manager"],
        },
        "events": events,
        "fallback": {
            "argv": argv("fallback_argv")?,
            "interpreter": interpreter,
            "package_roles": ["fallback_entrypoint"],
        },
        "generated_at": generated_at,
        "harness": "codex",
        "installation_id": signer.installation_id,
        "interpreter": interpreter,
        "package_version": text("package_version")?,
        "packaged_files": packaged,
        "schema_version": SCHEMA_VERSION,
        "transport": transport,
    });
    let fields =
        sign_local_authority_payload(&unsigned, signer.key, signer.key_id, PURPOSE, &generated_at)
            .map_err(str::to_owned)?;
    let mut manifest = unsigned;
    manifest["authentication"] = json!({
        "algorithm": ALGORITHM,
        "integrity_version": fields.integrity_version,
        "payload_hash": fields.payload_hash,
        "payload_mac": fields.payload_mac,
        "integrity_key_id": fields.integrity_key_id,
        "signed_at": fields.signed_at,
    });
    Ok(manifest)
}

fn strings(value: Option<&Value>) -> Option<Vec<Value>> {
    let items = value?.as_array()?;
    items.iter().all(Value::is_string).then(|| items.clone())
}

fn spelled(path: &Path) -> String {
    canonical(path).to_string_lossy().into_owned()
}

/// `datetime.now(timezone.utc).isoformat()`.
fn now_iso() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_micros())
        .unwrap_or_default();
    let seconds = (micros / 1_000_000) as f64 + (micros % 1_000_000) as f64 / 1_000_000.0;
    crate::approval_gate_state::iso_from_epoch(seconds)
}

fn refused(role: &str, kind: &str) -> String {
    format!("codex_hook_{role}_{kind}")
}

/// `describe_regular_file`: the canonical path, mode, owner, size and digest
/// of one regular file, refused under the rules `validate_regular_file` applies.
pub(crate) fn describe_regular(
    path: &Path,
    role: &str,
    executable_required: bool,
    package_roots: &[PathBuf],
) -> Result<Value, String> {
    let canonical_path = canonical(path);
    let (facts, file) = admit(&canonical_path, role, executable_required, package_roots)?;
    let digest = sha256_file(file, facts.size).ok_or_else(|| refused(role, "hash_mismatch"))?;
    Ok(json!({
        "executable_required": executable_required,
        "mode": facts.mode & 0o7777,
        "owner_uid": facts.uid,
        "path": canonical_path.to_string_lossy(),
        "role": role,
        "sha256": digest,
        "size": facts.size,
    }))
}

/// `describe_executable_file`: the invocation path as written, its link, and
/// the regular file it resolves to. A virtual-environment interpreter is
/// usually a link, and running only its target would escape the environment.
pub(crate) fn describe_executable(
    path: &Path,
    role: &str,
    package_roots: &[PathBuf],
) -> Result<Value, String> {
    let invocation = std::path::absolute(path).map_err(|_| refused(role, "missing"))?;
    let metadata = fs::symlink_metadata(&invocation).map_err(|_| refused(role, "missing"))?;
    let target = fs::canonicalize(&invocation).map_err(|_| refused(role, "missing"))?;
    let is_link = metadata.file_type().is_symlink();
    if !is_link && !metadata.file_type().is_file() {
        return Err(refused(role, "not_regular"));
    }
    let owner = invocation_owner(&metadata);
    if cfg!(unix) && current_uid().is_some_and(|uid| owner != uid && owner != 0) {
        return Err(refused(role, "owner_untrusted"));
    }
    if !executable(&invocation) {
        return Err(refused(role, "not_executable"));
    }
    let link_target = if is_link {
        let link = fs::read_link(&invocation).map_err(|_| refused(role, "missing"))?;
        Value::String(link.to_string_lossy().into_owned())
    } else {
        Value::Null
    };
    Ok(json!({
        "invocation_mode": invocation_mode(&invocation, &metadata),
        "invocation_owner_uid": owner,
        "invocation_path": invocation.to_string_lossy(),
        "link_target": link_target,
        "role": role,
        "target": describe_regular(&canonical(&target), role, true, package_roots)?,
    }))
}

#[cfg(unix)]
fn invocation_owner(metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::uid(metadata)
}

#[cfg(not(unix))]
fn invocation_owner(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn invocation_mode(_path: &Path, metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::mode(metadata) & 0o7777
}

#[cfg(not(unix))]
fn invocation_mode(path: &Path, metadata: &fs::Metadata) -> u32 {
    crate::codex_hook_file_identity_op::FileFacts::of(path, metadata).mode & 0o7777
}

/// `python_bridge_argv`: the legacy Python argv inside a native prefix.
fn bridge_argv(argv: &[Value]) -> &[Value] {
    let prefixed = argv.len() > 3
        && argv[0].as_str().is_some_and(|first| !first.is_empty())
        && argv[1].as_str() == Some(BRIDGE_COMMAND);
    if prefixed {
        &argv[2..]
    } else {
        argv
    }
}

/// `bridge_argv_sha256`: SHA-256 of the argv as ASCII-only compact JSON.
pub(crate) fn bridge_argv_sha256(argv: &[Value]) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut text = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        &Value::Array(bridge_argv(argv).to_vec()),
        &mut text,
        16 * 1024 * 1024,
        "codex_hook_bridge_argv_too_large",
    )
    .ok()?;
    Some(hex::encode(Sha256::digest(&text)))
}

fn event_argvs(manifest: &Map<String, Value>) -> impl Iterator<Item = &Vec<Value>> {
    manifest
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| event.get("argv").and_then(Value::as_array))
}

fn last_unique(items: Vec<String>) -> Vec<String> {
    let mut unique: Vec<String> = Vec::new();
    for item in items {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    let skip = unique.len().saturating_sub(MAX_GENERATIONS);
    unique.split_off(skip)
}

/// `compatible_bridge_argv_hashes`.
pub(crate) fn compatible_hashes(previous: Option<&Map<String, Value>>) -> Vec<String> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let mut candidates: Vec<String> = previous
        .get("compatible_bridge_argv_sha256")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|hash| hash.len() == 64)
        .map(str::to_owned)
        .collect();
    for argv in event_argvs(previous) {
        if !argv.is_empty() && argv.iter().all(Value::is_string) {
            candidates.extend(bridge_argv_sha256(argv));
        }
    }
    last_unique(candidates)
}

/// `retained_bridge_generations`: complete predecessor identities whose
/// bridge argv is still compatible, carried under the new signature.
pub(crate) fn retained_generations(previous: Option<&Map<String, Value>>) -> Vec<Value> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let allowed = compatible_hashes(Some(previous));
    let mut candidates: Vec<Map<String, Value>> = previous
        .get("retained_bridge_generations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_object().cloned())
        .collect();
    let mut predecessor = previous.clone();
    for field in LEGACY_FIELDS {
        predecessor.remove(field);
    }
    candidates.push(predecessor);
    // Insertion-ordered by first digest, value replaced by the latest match,
    // as a Python dict assignment keeps it.
    let mut selected: Vec<(String, Map<String, Value>)> = Vec::new();
    for candidate in candidates {
        let digests: Vec<String> = event_argvs(&candidate)
            .filter_map(|argv| bridge_argv_sha256(argv))
            .filter(|digest| allowed.contains(digest))
            .collect();
        for digest in digests {
            match selected.iter_mut().find(|(key, _)| key == &digest) {
                Some(entry) => entry.1 = candidate.clone(),
                None => selected.push((digest, candidate.clone())),
            }
        }
    }
    let skip = selected.len().saturating_sub(MAX_GENERATIONS);
    selected
        .into_iter()
        .skip(skip)
        .map(|(_, generation)| Value::Object(generation))
        .collect()
}

#[cfg(all(test, unix))]
#[path = "codex_hook_manifest_build_tests.rs"]
mod tests;
