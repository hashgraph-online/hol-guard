//! Port of `contained_node_execution.py`, `contained_typescript_execution.py`,
//! `contained_workspace_write_execution.py`, `contained_package_script_execution.py`,
//! plus the shared contained-execution support modules they depend on
//! (`runtime/containment_contract.py`, `runtime/containment_executor.py`,
//! `runtime/containment_health.py`, `runtime/containment_outputs.py`,
//! `runtime/contained_execution_common.py`, `runtime/contained_test_hook.py`,
//! the retired `runtime/workspace_snapshot_inputs.py`, `runtime/typescript_snapshot_inputs.py`,
//! `runtime/local_node_runner_evidence.py`, `runtime/local_package_script_evidence.py`,
//! `runtime/local_node_runner_options.py`, `runtime/package_evidence_common.py`,
//! `runtime/protection_health.py`, `file_identity.py`) — consolidating the
//! contained-execution cluster into one crate-internal module.
//!
//! Wave-1 contract: public API names match Python symbol names
//! (`pub fn` / `pub struct` / `pub enum`), private helpers keep their `_` names
//! (Rust `fn`), `pub` visibility is reserved for symbols other files consume.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::effect_decision::{
    effect_decision_to_payload, evaluate_effect_decision, DecisionBasis, DecisionFactor,
    DecisionFactorSource, EffectAssessment, EffectBlastRadius, EffectConfidence, EffectDecision,
    EffectDecisionRequest, EffectEvidenceSource, EffectKind, EffectReversibility,
    EffectTargetScope, GuardAction, PositiveProof, ProofRequirement, ProofRoute,
    EFFECT_CONTRACT_SCHEMA_VERSION, EFFECT_DECISION_SCHEMA_VERSION,
};
use crate::package_intent_parser::parse_package_intent;

// ===========================================================================
// file_identity.py (:1-33)
// ===========================================================================

/// `content_stat_identity` (:23-32) — compact stat tuple used to detect
/// content/path replacement.
fn content_stat_identity(metadata: &fs::Metadata) -> [u64; 6] {
    [
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime() as u64,
        metadata.ctime() as u64,
        metadata.mode() as u64,
    ]
}

/// Weak canonicalization — lexical cleanup plus `canonicalize` when the path
/// exists; mirrors `Path.resolve(strict=False)` on POSIX.
fn weak_canonicalize(path: &Path) -> PathBuf {
    if let Ok(p) = path.canonicalize() {
        return p;
    }
    // Lexical normalization for non-existent tails: collapse `.`/`..`.
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ===========================================================================
// containment_contract.py (:1-434)
// ===========================================================================

const CONTAINMENT_SCHEMA_VERSION: &str = "containment-contract-v1";
const MAX_TOKEN: usize = 256;
const MAX_TOKENS: usize = 256;
const MAX_PATH_ITEM: usize = 4096;
const MAX_PATH_ITEMS: usize = 4096;
const MAX_INPUTS: usize = 4096;
const MAX_DOMAIN: usize = 255;
const MAX_IDENTITY: usize = 4096;

/// `ContainmentAction` (:36-43).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContainmentAction {
    Read,
    Run,
    Write,
    Delete,
}

impl ContainmentAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            ContainmentAction::Read => "read",
            ContainmentAction::Run => "run",
            ContainmentAction::Write => "write",
            ContainmentAction::Delete => "delete",
        }
    }
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "run" => Some(Self::Run),
            "write" => Some(Self::Write),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// `ContainmentPolicy` (:46-78).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentPolicy {
    pub schema_version: String,
    pub action: ContainmentAction,
    pub workspace_read_paths: Vec<String>,
    pub workspace_write_paths: Vec<String>,
    pub env_allowlist: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub timeout_seconds: u64,
    pub max_processes: u32,
    pub max_open_files: u32,
    pub max_file_size_bytes: u64,
    pub max_write_bytes_total: u64,
    pub max_output_bytes: u64,
    pub memory_mb: u32,
    pub additional_read_paths: Vec<String>,
    pub allow_outbound_network: bool,
}

/// `ContainmentRequest` (:81-90).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentRequest {
    pub schema_version: String,
    pub kind: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env_allowlist: Vec<String>,
    pub timeout_seconds: u64,
    pub max_output_bytes: u64,
    pub additional_read_paths: Vec<String>,
    pub allow_outbound_network: bool,
}
impl ContainmentAction {
    /// Parse the wire `action` string (snake_case, e.g. `"run"`).
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::from_str(s)
    }
}

fn _cs_str(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(|s| s.to_owned())
}
fn _cs_str_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|i| i.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}
fn _cs_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key)?.as_u64()
}
fn _cs_u32(v: &Value, key: &str) -> Option<u32> {
    v.get(key)?.as_u64().map(|n| n as u32)
}
fn _cs_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

impl ContainmentRequest {
    /// Build from a Python-wire dict (snake_case keys).
    pub fn from_dict(v: &Value) -> Option<Self> {
        Some(Self {
            schema_version: _cs_str(v, "schema_version")?,
            kind: _cs_str(v, "kind")?,
            argv: _cs_str_list(v, "argv"),
            cwd: _cs_str(v, "cwd")?,
            env_allowlist: _cs_str_list(v, "env_allowlist"),
            timeout_seconds: _cs_u64(v, "timeout_seconds")?,
            max_output_bytes: _cs_u64(v, "max_output_bytes")?,
            additional_read_paths: _cs_str_list(v, "additional_read_paths"),
            allow_outbound_network: _cs_bool(v, "allow_outbound_network"),
        })
    }
}

impl ContainmentPolicy {
    /// Build from a Python-wire dict (snake_case keys).
    pub fn from_dict(v: &Value) -> Option<Self> {
        Some(Self {
            schema_version: _cs_str(v, "schema_version")?,
            action: ContainmentAction::from_str(&_cs_str(v, "action")?)?,
            workspace_read_paths: _cs_str_list(v, "workspace_read_paths"),
            workspace_write_paths: _cs_str_list(v, "workspace_write_paths"),
            env_allowlist: _cs_str_list(v, "env_allowlist"),
            allowed_domains: _cs_str_list(v, "allowed_domains"),
            timeout_seconds: _cs_u64(v, "timeout_seconds")?,
            max_processes: _cs_u32(v, "max_processes")?,
            max_open_files: _cs_u32(v, "max_open_files")?,
            max_file_size_bytes: _cs_u64(v, "max_file_size_bytes")?,
            max_write_bytes_total: _cs_u64(v, "max_write_bytes_total")?,
            max_output_bytes: _cs_u64(v, "max_output_bytes")?,
            memory_mb: _cs_u32(v, "memory_mb")?,
            additional_read_paths: _cs_str_list(v, "additional_read_paths"),
            allow_outbound_network: _cs_bool(v, "allow_outbound_network"),
        })
    }
}

/// `ContainmentAttestation` (:93-100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentAttestation {
    pub schema_version: String,
    pub enforcement: String,
    pub profile_digest: String,
    pub started_epoch_ms: u64,
    pub exit_code: i32,
    pub outputs: Vec<ContainmentCapturedOutput>,
    pub artifact_manifests: Vec<String>,
}

/// `ContainmentCapturedOutput` (containment_outputs.py :17-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentCapturedOutput {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

/// `ContainmentInput` (containment_contract.py :77-79 structural analogue).
/// Python `inputs` items are opaque dicts; we use a canonical JSON map.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainmentInput {
    pub path: String,
    pub resolved_path: String,
    pub sha256: String,
    pub kind: String,
}

/// `HealthSeverity` / `ProtectionCheckStatus` / `ProtectionSignal`
/// (protection_health.py :17-66).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionCheckStatus {
    Ok,
    Degraded,
    Unknown,
    Failed,
}

impl ProtectionCheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Unknown => "unknown",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionSignal {
    pub id: String,
    pub status: ProtectionCheckStatus,
    pub summary: String,
    pub details: Vec<String>,
    pub observed_epoch: Option<f64>,
    pub evidence: Option<Value>,
}

// --- containment_contract validators (:105-274) ---------------------------

static STABLE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_-]{1,63}$").unwrap());
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    )
    .unwrap()
});
static SHA256_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^sha256:[0-9a-f]{64}$").unwrap());
static ENV_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$").unwrap());

fn _reject(condition: bool, code: &'static str) -> Result<(), String> {
    if condition {
        Err(code.to_owned())
    } else {
        Ok(())
    }
}

/// `validate_containment_policy` (:105-165).
pub fn validate_containment_policy(policy: &ContainmentPolicy) -> Result<(), String> {
    _reject(
        policy.schema_version != CONTAINMENT_SCHEMA_VERSION,
        "policy_schema",
    )?;
    _reject(policy.timeout_seconds > 3_600, "policy_timeout")?;
    _reject(
        policy.max_processes > 1024 || policy.max_open_files > 65_536,
        "policy_resource_cap",
    )?;
    _reject(
        policy.max_file_size_bytes > (u64::MAX / 2),
        "policy_file_size",
    )?;
    _reject(
        policy.max_write_bytes_total > (u64::MAX / 2),
        "policy_write_total",
    )?;
    _reject(policy.max_output_bytes > (1 << 30), "policy_output")?;
    _reject(policy.memory_mb > (1 << 20), "policy_memory")?;
    _reject(
        policy.workspace_read_paths.len() > MAX_PATH_ITEMS,
        "policy_paths",
    )?;
    for path in &policy.workspace_read_paths {
        _reject(path.is_empty() || path.len() > MAX_PATH_ITEM, "policy_path")?;
    }
    _reject(
        policy.workspace_write_paths.is_empty() && policy.action != ContainmentAction::Read,
        "policy_write_paths",
    )?;
    _reject(
        policy.workspace_write_paths.len() > MAX_PATH_ITEMS,
        "policy_paths",
    )?;
    for path in &policy.workspace_write_paths {
        _reject(path.is_empty() || path.len() > MAX_PATH_ITEM, "policy_path")?;
        _reject(!path.starts_with('/'), "policy_write_rooted")?;
    }
    _reject(policy.env_allowlist.len() > MAX_TOKENS, "policy_env")?;
    for name in &policy.env_allowlist {
        _reject(!ENV_NAME.is_match(name), "policy_env_name")?;
    }
    _reject(
        policy.allowed_domains.len() > MAX_PATH_ITEMS,
        "policy_domains",
    )?;
    for domain in &policy.allowed_domains {
        _reject(
            domain.is_empty()
                || domain.len() > MAX_DOMAIN
                || !DOMAIN_RE.is_match(&domain.to_lowercase()),
            "policy_domain",
        )?;
    }
    _reject(
        policy.additional_read_paths.len() > MAX_PATH_ITEMS,
        "policy_paths",
    )?;
    for path in &policy.additional_read_paths {
        _reject(path.is_empty() || path.len() > MAX_PATH_ITEM, "policy_path")?;
    }
    Ok(())
}

/// `validate_containment_request` (:168-219).
pub fn validate_containment_request(request: &ContainmentRequest) -> Result<(), String> {
    _reject(
        request.schema_version != CONTAINMENT_SCHEMA_VERSION,
        "request_schema",
    )?;
    _reject(
        request.kind.is_empty() || !STABLE_ID.is_match(&request.kind),
        "request_kind",
    )?;
    _reject(
        request.argv.is_empty() || request.argv.len() > MAX_TOKENS,
        "request_argv",
    )?;
    _reject(
        !request.cwd.starts_with('/') || request.cwd.len() > MAX_PATH_ITEM,
        "request_cwd",
    )?;
    for token in &request.argv {
        _reject(token.is_empty() || token.len() > MAX_TOKEN, "request_arg")?;
        _reject(token.contains('\0'), "request_arg_nul")?;
    }
    _reject(
        request.timeout_seconds == 0 || request.timeout_seconds > 3_600,
        "request_timeout",
    )?;
    _reject(
        request.max_output_bytes == 0 || request.max_output_bytes > (1 << 30),
        "request_output",
    )?;
    _reject(request.env_allowlist.len() > MAX_TOKENS, "request_env")?;
    for name in &request.env_allowlist {
        _reject(!ENV_NAME.is_match(name), "request_env_name")?;
    }
    _reject(
        request.additional_read_paths.len() > MAX_PATH_ITEMS,
        "request_paths",
    )?;
    for path in &request.additional_read_paths {
        _reject(
            path.is_empty() || path.len() > MAX_PATH_ITEM,
            "request_path",
        )?;
    }
    Ok(())
}

/// `validate_containment_attestation` (:222-274).
pub fn validate_containment_attestation(
    attestation: &ContainmentAttestation,
) -> Result<(), String> {
    _reject(
        attestation.schema_version != CONTAINMENT_SCHEMA_VERSION,
        "attestation_schema",
    )?;
    _reject(
        !STABLE_ID.is_match(&attestation.enforcement),
        "attestation_enforcement",
    )?;
    _reject(
        attestation.profile_digest.is_empty() || attestation.profile_digest.len() > MAX_IDENTITY,
        "attestation_digest",
    )?;
    _reject(
        attestation.started_epoch_ms > u64::MAX / 2,
        "attestation_started",
    )?;
    _reject(
        attestation.exit_code < -255 || attestation.exit_code > 255,
        "attestation_exit",
    )?;
    _reject(
        attestation.outputs.len() > MAX_INPUTS,
        "attestation_outputs",
    )?;
    for output in &attestation.outputs {
        _reject(
            output.relative_path.is_empty() || output.relative_path.len() > MAX_PATH_ITEM,
            "output_path",
        )?;
        _reject(!SHA256_RE.is_match(&output.sha256), "output_sha256")?;
        _reject(output.size_bytes > (1 << 30), "output_size")?;
        _reject(output.media_type.len() > MAX_TOKEN, "output_media")?;
    }
    _reject(
        attestation.artifact_manifests.len() > MAX_PATH_ITEMS,
        "attestation_manifests",
    )?;
    Ok(())
}

// --- containment_contract helpers (:281-433) -------------------------------

/// `_dedupe` (:281-283).
fn _dedupe(items: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item.clone());
        }
    }
    out
}

/// `_first_frozen_token` (:286-293).
fn _first_frozen_token(argv: &[String]) -> Option<String> {
    argv.first().and_then(|t| {
        Path::new(t)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
    })
}

/// `_workspace_path` (:296-300).
fn _workspace_path(request: &ContainmentRequest) -> PathBuf {
    PathBuf::from(&request.cwd)
}

/// `_workspace_contains` (:303-315).
fn _workspace_contains(workspace: &Path, candidate: &str) -> bool {
    let resolved = weak_canonicalize(&workspace.join(candidate));
    resolved.starts_with(workspace)
}

/// `_normalize_env` (:318-324).
fn _normalize_env(names: &[String]) -> Vec<String> {
    let mut filtered: Vec<String> = names
        .iter()
        .filter(|n| ENV_NAME.is_match(n))
        .cloned()
        .collect();
    filtered.sort();
    filtered.dedup();
    filtered
}

/// `_workspace_basename` (:327-331).
fn _workspace_basename(request: &ContainmentRequest) -> String {
    Path::new(&request.cwd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_owned()
}

/// `_containment_profile_payload` (:334-373).
fn _containment_profile_payload(
    request: &ContainmentRequest,
    policy: &ContainmentPolicy,
    enforcement: &str,
) -> Value {
    let env_allowlist = _normalize_env(&request.env_allowlist);
    let write_paths = _dedupe(&policy.workspace_write_paths);
    let read_paths = _dedupe(&policy.workspace_read_paths);
    let additional = _dedupe(&request.additional_read_paths);
    json!({
        "schema_version": request.schema_version,
        "kind": request.kind,
        "argv": request.argv,
        "cwd": request.cwd,
        "env_allowlist": env_allowlist,
        "timeout_seconds": request.timeout_seconds,
        "max_output_bytes": request.max_output_bytes,
        "allow_outbound_network": request.allow_outbound_network,
        "additional_read_paths": additional,
        "workspace_read_paths": read_paths,
        "workspace_write_paths": write_paths,
        "allowed_domains": policy.allowed_domains,
        "max_processes": policy.max_processes,
        "max_open_files": policy.max_open_files,
        "max_file_size_bytes": policy.max_file_size_bytes,
        "max_write_bytes_total": policy.max_write_bytes_total,
        "memory_mb": policy.memory_mb,
        "enforcement": enforcement,
        "workspace": _workspace_basename(request),
        "entrypoint": _first_frozen_token(&request.argv),
    })
}

/// `containment_profile_digest` (:376-383).
pub fn containment_profile_digest(
    request: &ContainmentRequest,
    policy: &ContainmentPolicy,
    enforcement: &str,
) -> String {
    let payload = _containment_profile_payload(request, policy, enforcement);
    let mut buf = Vec::new();
    let _ = guard_contracts::write_canonical_json(&payload, &mut buf);
    format!("sha256:{}", hex::encode(Sha256::digest(&buf)))
}

/// `resolve_workspace_path` (:386-395).
pub fn resolve_workspace_path(workspace: &Path, raw: &str) -> Option<PathBuf> {
    if raw.is_empty() || raw.len() > MAX_PATH_ITEM {
        return None;
    }
    let candidate = weak_canonicalize(&workspace.join(raw));
    if !candidate.starts_with(workspace) {
        return None;
    }
    Some(candidate)
}

// ===========================================================================
// containment_outputs.py (:1-189)
// ===========================================================================

const MAX_CAPTURED_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_CAPTURED_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OUTPUT_FILES: usize = 128;
const CAPTURED_OUTPUT_MEDIA_TYPE: &str = "application/octet-stream";

/// `OutputBoundaryError` (:12-14) → `Err(String)`.
///
/// `captured_file_output` (:28-80): read a bounded file, emit digest + bytes.
fn captured_file_output(path: &Path) -> Result<(ContainmentCapturedOutput, Vec<u8>), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "output_unreadable".to_owned())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("output_not_regular".to_owned());
    }
    if meta.size() > MAX_CAPTURED_OUTPUT_BYTES {
        return Err("output_too_large".to_owned());
    }
    let mut file = File::open(path).map_err(|_| "output_unreadable".to_owned())?;
    let before = file
        .metadata()
        .map_err(|_| "output_unreadable".to_owned())?;
    let mut content: Vec<u8> =
        Vec::with_capacity(meta.size().min(MAX_CAPTURED_OUTPUT_BYTES) as usize);
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|_| "output_unreadable".to_owned())?;
        if read == 0 {
            break;
        }
        content.extend_from_slice(&buf[..read]);
        if content.len() as u64 > MAX_CAPTURED_OUTPUT_BYTES {
            return Err("output_too_large".to_owned());
        }
    }
    let after = file
        .metadata()
        .map_err(|_| "output_unreadable".to_owned())?;
    if content_stat_identity(&before) != content_stat_identity(&after) {
        return Err("output_changed_during_capture".to_owned());
    }
    let relative = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_owned();
    Ok((
        ContainmentCapturedOutput {
            relative_path: relative,
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(&content))),
            size_bytes: content.len() as u64,
            media_type: CAPTURED_OUTPUT_MEDIA_TYPE.to_owned(),
        },
        content,
    ))
}

/// `read_verified_output` (:83-186).
pub fn read_verified_output(path: &Path) -> Result<ContainmentCapturedOutput, String> {
    let (output, _) = captured_file_output(path)?;
    Ok(output)
}

// ===========================================================================
// containment_executor.py (:1-496)
// ===========================================================================

const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";

pub(crate) fn _now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn _platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// `write_manifest_atomically` (containment_executor.py :47-58).
fn write_manifest_atomically(path: &Path, payload: &Value) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "manifest_parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|_| "manifest_parent".to_owned())?;
    let tmp = path.with_extension("tmp");
    let mut buf = Vec::new();
    guard_contracts::write_canonical_json(payload, &mut buf)
        .map_err(|_| "manifest_serialize".to_owned())?;
    {
        let mut file = File::create(&tmp).map_err(|_| "manifest_write".to_owned())?;
        file.write_all(&buf)
            .map_err(|_| "manifest_write".to_owned())?;
        file.sync_all().map_err(|_| "manifest_write".to_owned())?;
    }
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|_| "manifest_write".to_owned())?;
    fs::rename(&tmp, path).map_err(|_| "manifest_write".to_owned())?;
    Ok(())
}

/// `execute_contained` (:61-203): run the request's argv under containment.
/// Platform-specific seatbelt/bwrap argv builders are retained as pure fns so
/// the shell-out surface stays narrow; the launcher uses `std::process::Command`
/// because the crate denies `unsafe`.
#[allow(clippy::type_complexity)]
pub fn execute_contained(
    request: &ContainmentRequest,
    policy: &ContainmentPolicy,
    guard_home: &Path,
    run_id: &str,
) -> Result<
    (
        i32,
        String,
        String,
        Vec<ContainmentCapturedOutput>,
        u64,
        String,
        Vec<String>,
    ),
    String,
> {
    validate_containment_request(request)?;
    validate_containment_policy(policy)?;

    let workspace = _workspace_path(request);
    let run_dir = guard_home.join("containment").join(run_id);
    fs::create_dir_all(&run_dir).map_err(|_| "containment_run_dir".to_owned())?;
    let stdout_path = run_dir.join("stdout.bin");
    let stderr_path = run_dir.join("stderr.bin");
    let manifest_path = run_dir.join("attestation.json");

    let platform = _platform();
    let enforcement = match platform {
        "darwin" => "seatbelt",
        "linux" => "bubblewrap",
        _ => "unsandboxed",
    };
    let profile_digest = containment_profile_digest(request, policy, enforcement);

    let argv = match platform {
        "darwin" => _darwin_seatbelt_argv(request, policy, &run_dir)?,
        "linux" => _linux_bwrap_argv(request, policy)?,
        _ => request.argv.clone(),
    };
    if argv.is_empty() {
        return Err("containment_argv".to_owned());
    }

    let mut child_env: BTreeMap<String, String> = BTreeMap::new();
    for name in _normalize_env(&request.env_allowlist) {
        if let Ok(value) = std::env::var(&name) {
            child_env.insert(name, value);
        }
    }
    child_env.insert("HOME".to_owned(), workspace.to_string_lossy().into_owned());
    child_env.insert("TMPDIR".to_owned(), run_dir.to_string_lossy().into_owned());
    child_env.insert("HOL_GUARD_CONTAINED".to_owned(), "1".to_owned());
    child_env.insert("HOL_GUARD_RUN_ID".to_owned(), run_id.to_owned());

    let stdout_file = File::create(&stdout_path).map_err(|_| "containment_stdout".to_owned())?;
    let stderr_file = File::create(&stderr_path).map_err(|_| "containment_stderr".to_owned())?;

    let started = _now_epoch_ms();
    let spawn = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(&workspace)
        .env_clear()
        .envs(&child_env)
        .stdin(Stdio::null())
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn();
    let mut child = match spawn {
        Ok(c) => c,
        Err(e) => return Err(format!("containment_spawn:{e}")),
    };
    let wait_started = Instant::now();
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if wait_started.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("containment_timeout".to_owned());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("containment_wait:{e}")),
        }
    };
    let exit_code = status.code().unwrap_or(-1);

    // Capture bounded outputs — every file in run_dir besides the manifest.
    let mut outputs = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut captured: Vec<String> = Vec::new();
    let entries = fs::read_dir(&run_dir).map_err(|_| "containment_outputs".to_owned())?;
    let mut count = 0usize;
    for entry in entries {
        let entry = entry.map_err(|_| "containment_outputs".to_owned())?;
        count += 1;
        if count > MAX_OUTPUT_FILES {
            return Err("containment_output_count".to_owned());
        }
        let path = entry.path();
        if path == manifest_path {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "stdout.bin" && name != "stderr.bin" {
            continue;
        }
        let (output, _) = captured_file_output(&path)?;
        total_bytes += output.size_bytes;
        if total_bytes > MAX_TOTAL_CAPTURED_OUTPUT_BYTES {
            return Err("containment_output_bytes".to_owned());
        }
        captured.push(name);
        outputs.push(output);
    }

    let attestation = json!({
        "schema_version": CONTAINMENT_SCHEMA_VERSION,
        "enforcement": enforcement,
        "profile_digest": profile_digest,
        "started_epoch_ms": started,
        "exit_code": exit_code,
        "outputs": outputs.iter().map(|o| json!({
            "relative_path": o.relative_path,
            "sha256": o.sha256,
            "size_bytes": o.size_bytes,
            "media_type": o.media_type,
        })).collect::<Vec<_>>(),
        "artifact_manifests": [],
    });
    write_manifest_atomically(&manifest_path, &attestation)?;

    let stdout_text = fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr_text = fs::read_to_string(&stderr_path).unwrap_or_default();
    Ok((
        exit_code,
        stdout_text,
        stderr_text,
        outputs,
        started,
        enforcement.to_owned(),
        captured,
    ))
}

/// `_darwin_seatbelt_argv` (:206-361): build a seatbelt profile argv. The
/// sandbox-exec profile is generated on the fly into `run_dir/profile.sb`.
pub(crate) fn _darwin_seatbelt_argv(
    request: &ContainmentRequest,
    policy: &ContainmentPolicy,
    run_dir: &Path,
) -> Result<Vec<String>, String> {
    let profile_path = run_dir.join("profile.sb");
    let workspace = _workspace_path(request);
    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}\"))\n",
        workspace.to_string_lossy()
    ));
    for path in &policy.workspace_read_paths {
        profile.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }
    for path in &request.additional_read_paths {
        profile.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }
    for path in &policy.workspace_write_paths {
        profile.push_str(&format!("(allow file-write* (subpath \"{path}\"))\n"));
    }
    profile.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n",
        run_dir.to_string_lossy()
    ));
    if request.allow_outbound_network {
        profile.push_str("(allow network-outbound)\n");
    }
    fs::write(&profile_path, profile).map_err(|_| "seatbelt_profile".to_owned())?;
    let mut argv = vec![
        "/usr/bin/sandbox-exec".to_owned(),
        "-f".to_owned(),
        profile_path.to_string_lossy().into_owned(),
    ];
    argv.extend(request.argv.iter().cloned());
    Ok(argv)
}

/// `_linux_bwrap_argv` (:364-443): build a bubblewrap argv.
pub(crate) fn _linux_bwrap_argv(
    request: &ContainmentRequest,
    policy: &ContainmentPolicy,
) -> Result<Vec<String>, String> {
    let workspace = _workspace_path(request);
    let mut argv = vec![BUBBLEWRAP_PATH.to_owned()];
    argv.extend(["--die-with-parent".to_owned(), "--unshare-all".to_owned()]);
    if !request.allow_outbound_network {
        argv.push("--unshare-net".to_owned());
    }
    argv.extend([
        "--bind".to_owned(),
        workspace.to_string_lossy().into_owned(),
        workspace.to_string_lossy().into_owned(),
    ]);
    for path in &policy.workspace_read_paths {
        argv.extend(["--ro-bind".to_owned(), path.clone(), path.clone()]);
    }
    for path in &request.additional_read_paths {
        argv.extend(["--ro-bind".to_owned(), path.clone(), path.clone()]);
    }
    for path in &policy.workspace_write_paths {
        argv.extend(["--bind".to_owned(), path.clone(), path.clone()]);
    }
    argv.extend([
        "--chdir".to_owned(),
        workspace.to_string_lossy().into_owned(),
    ]);
    argv.push("--".to_owned());
    argv.extend(request.argv.iter().cloned());
    Ok(argv)
}

/// `canonical_json` (:82-87) — `json.dumps(sort_keys=True, separators)`.
pub(crate) fn _canonical_json(payload: &Value) -> Vec<u8> {
    crate::contained_runner::common::canonical_bytes(payload).unwrap_or_default()
}

// ===========================================================================
// containment_health.py (:1-332)
// ===========================================================================

/// `ContainmentHealthEvidence` (:48-79).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainmentHealthEvidence {
    pub status: ProtectionCheckStatus,
    pub checks: Vec<String>,
    pub observations: Vec<String>,
    pub failures: Vec<String>,
    pub observed_epoch: Option<f64>,
}

/// `load_current_containment_health` (:82-171): read
/// `$GUARD_HOME/protection/containment.json`.
pub fn load_current_containment_health(guard_home: &Path) -> Option<ContainmentHealthEvidence> {
    const MAX_HEALTH_BYTES: u64 = 64 * 1024;
    let path = guard_home.join("protection").join("containment.json");
    let meta = fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.size() > MAX_HEALTH_BYTES {
        return None;
    }
    let text = fs::read_to_string(&path).ok()?;
    let payload: Value = serde_json::from_str(&text).ok()?;
    let obj = payload.as_object()?;
    let status = match obj.get("status").and_then(|v| v.as_str()).unwrap_or("") {
        "ok" => ProtectionCheckStatus::Ok,
        "degraded" => ProtectionCheckStatus::Degraded,
        "unknown" => ProtectionCheckStatus::Unknown,
        "failed" => ProtectionCheckStatus::Failed,
        _ => return None,
    };
    let list = |key: &str| -> Vec<String> {
        obj.get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| i.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(ContainmentHealthEvidence {
        status,
        checks: list("checks"),
        observations: list("observations"),
        failures: list("failures"),
        observed_epoch: obj.get("observed_epoch").and_then(|v| v.as_f64()),
    })
}

/// `containment_positive_proof` (:175-244).
pub fn contained_positive_proof(
    health: Option<&ContainmentHealthEvidence>,
    enforcement: &str,
    profile_digest: &str,
    attestation_digest: &str,
    satisfied_requirements: &[ProofRequirement],
) -> Result<PositiveProof, String> {
    let Some(health) = health else {
        return Err("containment_health_missing".to_owned());
    };
    if health.status != ProtectionCheckStatus::Ok {
        return Err("containment_health_degraded".to_owned());
    }
    if enforcement.is_empty() || enforcement == "unsandboxed" {
        return Err("containment_unsandboxed".to_owned());
    }
    if !SHA256_RE.is_match(profile_digest) || !SHA256_RE.is_match(attestation_digest) {
        return Err("containment_digest_mismatch".to_owned());
    }
    let binding = format!("{enforcement}:{profile_digest}:{attestation_digest}");
    Ok(PositiveProof {
        route: ProofRoute::Contained,
        binding_digest: format!("sha256:{}", hex::encode(Sha256::digest(binding.as_bytes()))),
        satisfied_requirements: satisfied_requirements.to_vec(),
        enforced: true,
    })
}

// ===========================================================================
// package_intent_parser callers — thin wrapper
// ===========================================================================

fn _parse_intent(command_text: &str) -> Option<crate::package_intent_common::PackageIntent> {
    parse_package_intent(command_text, None, None, None, None)
}

// ===========================================================================
// workspace-write path helpers
// ===========================================================================

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

fn _is_protected_path(relative: &Path) -> bool {
    relative
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .any(|part| PROTECTED_NAMES.contains(&part))
}

pub(crate) fn _canonical_directory(root: &Path) -> Result<PathBuf, String> {
    let canonical = root
        .canonicalize()
        .map_err(|_| "workspace_unreadable".to_owned())?;
    if !canonical.is_dir() {
        return Err("workspace_not_directory".to_owned());
    }
    Ok(canonical)
}

// ===========================================================================
// contained_workspace_write_execution.py (:1-415)
// ===========================================================================

/// `ContainedWriteOperation` (:30-40).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainedWriteOperation {
    pub kind: String,
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub source: Option<String>,
    pub mode: Option<u32>,
}

/// `ContainedWorkspaceWriteResult` (:43-50).
#[derive(Debug, Clone)]
pub struct ContainedWorkspaceWriteResult {
    pub attestation: ContainmentAttestation,
    pub outputs: Vec<ContainmentCapturedOutput>,
    pub captured_files: Vec<String>,
    pub applied: Vec<String>,
    pub decision: Option<EffectDecision>,
    pub stdout: String,
    pub stderr: String,
    pub proof: Option<PositiveProof>,
    pub operation_id: String,
    pub output_digest: Option<String>,
}

pub(crate) fn _safe_relative(workspace: &Path, raw: &str) -> Option<PathBuf> {
    resolve_workspace_path(workspace, raw)
}

fn _target_state(path: &Path) -> Result<(bool, Option<String>), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err("target_symlink".to_owned());
            }
            Ok((true, Some(format!("{:x}", meta.size()))))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((false, None)),
        Err(_) => Err("target_unreadable".to_owned()),
    }
}

fn _invocation(tokens: &[String]) -> Option<(String, Vec<ContainedWriteOperation>)> {
    // Compact `mkdir -p a b` / `printf ... > path` / `cp src dst` style ops.
    if tokens.is_empty() {
        return None;
    }
    match tokens[0].as_str() {
        "mkdir" if tokens.len() >= 3 && tokens[1] == "-p" => {
            let ops = tokens[2..]
                .iter()
                .map(|p| ContainedWriteOperation {
                    kind: "mkdir".to_owned(),
                    path: p.clone(),
                    content: None,
                    source: None,
                    mode: None,
                })
                .collect();
            Some(("mkdir".to_owned(), ops))
        }
        "cp" if tokens.len() == 3 => Some((
            "copy".to_owned(),
            vec![ContainedWriteOperation {
                kind: "copy".to_owned(),
                path: tokens[2].clone(),
                content: None,
                source: Some(tokens[1].clone()),
                mode: None,
            }],
        )),
        "mv" if tokens.len() == 3 => Some((
            "move".to_owned(),
            vec![ContainedWriteOperation {
                kind: "move".to_owned(),
                path: tokens[2].clone(),
                content: None,
                source: Some(tokens[1].clone()),
                mode: None,
            }],
        )),
        _ => None,
    }
}

pub(crate) fn _requirements(ops: &[ContainedWriteOperation]) -> Vec<ProofRequirement> {
    let mut req = vec![ProofRequirement::ContainmentIdentity];
    if ops.iter().any(|o| o.kind == "delete") {
        req.push(ProofRequirement::CapabilityConstraints);
    }
    req
}

pub(crate) fn _contained_decision(
    subject: &str,
    proof: PositiveProof,
    requirements: &[ProofRequirement],
) -> Option<EffectDecision> {
    let factor = DecisionFactor {
        source: DecisionFactorSource::Effect,
        reason_code: subject.to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::Allow,
            proof_route: Some(ProofRoute::Contained),
        },
        segment_ref: None,
        operation_ref: None,
        producer_ref: None,
        evidence_digest: Some(proof.binding_digest.clone()),
        assessment: Some(EffectAssessment {
            kind: EffectKind::WorkspaceWrite,
            target_scope: EffectTargetScope::Workspace,
            reversibility: EffectReversibility::Reversible,
            blast_radius: EffectBlastRadius::SingleResource,
            evidence_source: EffectEvidenceSource::Containment,
            confidence: EffectConfidence::Strong,
            containment: crate::effect_decision::ContainmentRequirement::Required,
            proof_requirements: requirements.to_vec(),
            uncertainty_reasons: vec![],
            schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
        }),
        proof: Some(proof),
    };
    evaluate_effect_decision(&EffectDecisionRequest {
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        factors: vec![factor],
        uncertainties: vec![],
    })
    .ok()
}

pub(crate) fn _proof_from_execution(
    request: &ContainmentRequest,
    policy: &ContainmentPolicy,
    enforcement: &str,
    health: Option<&ContainmentHealthEvidence>,
    exit_code: i32,
    outputs: &[ContainmentCapturedOutput],
    requirements: &[ProofRequirement],
) -> Result<PositiveProof, String> {
    if exit_code != 0 {
        return Err("contained_exec_failed".to_owned());
    }
    let profile_digest = containment_profile_digest(request, policy, enforcement);
    let attestation_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            json!({
                "exit_code": exit_code,
                "outputs": outputs.iter().map(|o| &o.sha256).collect::<Vec<_>>(),
            })
            .to_string()
            .as_bytes(),
        ))
    );
    contained_positive_proof(
        health,
        enforcement,
        &profile_digest,
        &attestation_digest,
        requirements,
    )
}

fn _result_without_promotion(
    attestation: ContainmentAttestation,
    outputs: Vec<ContainmentCapturedOutput>,
    captured: Vec<String>,
) -> ContainedWorkspaceWriteResult {
    ContainedWorkspaceWriteResult {
        attestation,
        outputs,
        captured_files: captured,
        applied: vec![],
        decision: None,
        stdout: String::new(),
        stderr: String::new(),
        proof: None,
        operation_id: "copy".to_owned(),
        output_digest: None,
    }
}

pub(crate) fn _promote_output(
    workspace: &Path,
    operation: &ContainedWriteOperation,
) -> Result<String, String> {
    let target =
        _safe_relative(workspace, &operation.path).ok_or_else(|| "target_unsafe".to_owned())?;
    match operation.kind.as_str() {
        "mkdir" => {
            fs::create_dir_all(&target).map_err(|_| "mkdir_failed".to_owned())?;
            Ok(operation.path.clone())
        }
        "write" => {
            let content = operation
                .content
                .as_ref()
                .ok_or_else(|| "write_missing_content".to_owned())?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|_| "write_parent".to_owned())?;
            }
            crate::semantic_workspace::write_atomic(&target, content, operation.mode)?;
            Ok(operation.path.clone())
        }
        "copy" => {
            let source = operation
                .source
                .as_ref()
                .ok_or_else(|| "copy_missing_source".to_owned())?;
            let source_path =
                _safe_relative(workspace, source).ok_or_else(|| "source_unsafe".to_owned())?;
            let (exists, _) = _target_state(&source_path)?;
            if !exists {
                return Err("source_missing".to_owned());
            }
            fs::copy(&source_path, &target).map_err(|_| "copy_failed".to_owned())?;
            Ok(operation.path.clone())
        }
        "move" => {
            let source = operation
                .source
                .as_ref()
                .ok_or_else(|| "move_missing_source".to_owned())?;
            let source_path =
                _safe_relative(workspace, source).ok_or_else(|| "source_unsafe".to_owned())?;
            fs::rename(&source_path, &target).map_err(|_| "move_failed".to_owned())?;
            Ok(operation.path.clone())
        }
        "delete" => {
            let (exists, _) = _target_state(&target)?;
            if !exists {
                return Err("delete_missing".to_owned());
            }
            if target.is_dir() {
                fs::remove_dir_all(&target).map_err(|_| "delete_failed".to_owned())?;
            } else {
                fs::remove_file(&target).map_err(|_| "delete_failed".to_owned())?;
            }
            Ok(operation.path.clone())
        }
        other => Err(format!("unsupported_op:{other}")),
    }
}

/// `try_execute_contained_workspace_write` (:56-141).
pub fn try_execute_contained_workspace_write(
    workspace: &Path,
    command_text: &str,
    guard_home: &Path,
) -> Option<ContainedWorkspaceWriteResult> {
    let tokens = shlex_split(command_text)?;
    let (subject, ops) = _invocation(&tokens)?;
    if ops.is_empty() {
        return None;
    }
    for op in &ops {
        _safe_relative(workspace, &op.path)?;
        if let Some(src) = &op.source {
            _safe_relative(workspace, src)?;
        }
    }
    let requirements = _requirements(&ops);
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "workspace-write".to_owned(),
        argv: tokens.clone(),
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: 60,
        max_output_bytes: 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Write,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 8,
        max_open_files: 256,
        max_file_size_bytes: 16 * 1024 * 1024,
        max_write_bytes_total: 32 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 256,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let run_id = format!("ws-write-{}", _now_epoch_ms());
    let (exit_code, _stdout_text, _stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
    let health = load_current_containment_health(guard_home);
    let proof = _proof_from_execution(
        &request,
        &policy,
        &enforcement,
        health.as_ref(),
        exit_code,
        &outputs,
        &requirements,
    )
    .ok();
    let profile_digest = containment_profile_digest(&request, &policy, &enforcement);
    let attestation = ContainmentAttestation {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        enforcement,
        profile_digest,
        started_epoch_ms: started_ms,
        exit_code,
        outputs: outputs.clone(),
        artifact_manifests: vec![],
    };
    let Some(proof) = proof else {
        return Some(_result_without_promotion(attestation, outputs, captured));
    };
    // Promotion — apply operations into the workspace once the proof is
    // established.
    let mut applied: Vec<String> = Vec::new();
    for op in &ops {
        match _promote_output(workspace, op) {
            Ok(path) => applied.push(path),
            Err(_) => return Some(_result_without_promotion(attestation, outputs, captured)),
        }
    }
    let decision = _contained_decision(&subject, proof, &requirements);
    Some(ContainedWorkspaceWriteResult {
        attestation,
        outputs,
        captured_files: captured,
        applied,
        decision,
        stdout: _stdout_text.clone(),
        stderr: _stderr_text.clone(),
        proof: None,
        operation_id: ops
            .first()
            .map(|o| o.kind.clone())
            .unwrap_or_else(|| "write".to_owned()),
        output_digest: None,
    })
}

/// POSIX-shell word splitting shared by the resident ops that receive a
///  contract field rather than a structured .
pub fn shlex_split(command_text: &str) -> Option<Vec<String>> {
    crate::command_launcher_floors::shlex_split(command_text).ok()
}

// ===========================================================================
// RTM-020 structured-intent entry points
//
// The four `try_execute_contained_*_with_intent` functions are the caller-side
// bindings of the resident ops. They accept the caller's *already-parsed*
// `LocalPackageExecutionEvidence` plus the exact `manager`/`argv` tuple so the
// kernel never has to `shlex`-join an argv back into `command_text` (which
// would re-parse quoting/escaping and could shift intent classification).
//
// `command_text` is retained in the contract so the resident can run the
// legacy self-parse for shadow comparison, but the *intent* binding comes
// from `manager`/`argv`/`evidence`, never from re-parsing `command_text`.
// ===========================================================================

/// Structured-intent binding for `try_execute_contained_workspace_write`.
/// No `manager`/`evidence` — the write op is fully described by `command_text`.
pub fn try_execute_contained_workspace_write_with_intent(
    workspace: &Path,
    argv: &[String],
    guard_home: &Path,
) -> Option<ContainedWorkspaceWriteResult> {
    let tokens: Vec<String> = argv.to_vec();
    let (subject, ops) = _invocation(&tokens)?;
    if ops.is_empty() {
        return None;
    }
    for op in &ops {
        _safe_relative(workspace, &op.path)?;
        if let Some(src) = &op.source {
            _safe_relative(workspace, src)?;
        }
    }
    let requirements = _requirements(&ops);
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "workspace-write".to_owned(),
        argv: tokens.clone(),
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: 60,
        max_output_bytes: 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Write,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 8,
        max_open_files: 256,
        max_file_size_bytes: 8 * 1024 * 1024,
        max_write_bytes_total: 16 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 512,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let run_id = format!("ww-{}", _now_epoch_ms());
    let (exit_code, _stdout_text, _stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
    let profile_digest = containment_profile_digest(&request, &policy, &enforcement);
    let attestation = ContainmentAttestation {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        enforcement: enforcement.clone(),
        profile_digest: profile_digest.clone(),
        started_epoch_ms: started_ms,
        exit_code,
        outputs: outputs.clone(),
        artifact_manifests: vec![],
    };
    let attestation_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            json!({
                "exit_code": exit_code,
                "outputs": outputs.iter().map(|o| &o.sha256).collect::<Vec<_>>(),
            })
            .to_string()
            .as_bytes(),
        ))
    );
    let health = load_current_containment_health(guard_home);
    let proof = contained_positive_proof(
        health.as_ref(),
        &enforcement,
        &profile_digest,
        &attestation_digest,
        &requirements,
    )
    .ok();
    let Some(proof) = proof else {
        return Some(_result_without_promotion(attestation, outputs, captured));
    };
    let mut applied: Vec<String> = Vec::new();
    for op in &ops {
        match _promote_output(workspace, op) {
            Ok(path) => applied.push(path),
            Err(_) => {
                return Some(_result_without_promotion(attestation, outputs, captured));
            }
        }
    }
    let decision = _contained_decision(&subject, proof, &requirements);
    Some(ContainedWorkspaceWriteResult {
        attestation,
        outputs,
        captured_files: captured,
        applied,
        decision,
        stdout: _stdout_text.clone(),
        stderr: _stderr_text.clone(),
        proof: None,
        operation_id: ops
            .first()
            .map(|o| o.kind.clone())
            .unwrap_or_else(|| "write".to_owned()),
        output_digest: None,
    })
}

// ===========================================================================
// RTM-020 to_dict impls — canonical JSON the resident op returns to Python.
// Each impl mirrors the Python `asdict(...)` output for the corresponding
// dataclass so the bridge can reconstruct the Python type verbatim.
// ===========================================================================

impl ContainmentCapturedOutput {
    /// Serialize to the `asdict` shape of `ContainmentCapturedOutput`.
    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("relative_path".to_owned(), json!(self.relative_path));
        m.insert("sha256".to_owned(), json!(self.sha256));
        m.insert("size_bytes".to_owned(), json!(self.size_bytes));
        m.insert("media_type".to_owned(), json!(self.media_type));
        Value::Object(m)
    }
}

impl ContainmentAttestation {
    /// Serialize to the `asdict` shape of `ContainmentAttestation`.
    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("schema_version".to_owned(), json!(self.schema_version));
        m.insert("enforcement".to_owned(), json!(self.enforcement));
        m.insert("profile_digest".to_owned(), json!(self.profile_digest));
        m.insert("started_epoch_ms".to_owned(), json!(self.started_epoch_ms));
        m.insert("exit_code".to_owned(), json!(self.exit_code));
        m.insert(
            "outputs".to_owned(),
            Value::Array(self.outputs.iter().map(|o| o.to_dict()).collect()),
        );
        m.insert(
            "artifact_manifests".to_owned(),
            json!(self.artifact_manifests),
        );
        Value::Object(m)
    }
}

impl ContainedWorkspaceWriteResult {
    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("attestation".to_owned(), self.attestation.to_dict());
        m.insert(
            "outputs".to_owned(),
            Value::Array(self.outputs.iter().map(|o| o.to_dict()).collect()),
        );
        m.insert(
            "captured_files".to_owned(),
            Value::Array(
                self.captured_files
                    .iter()
                    .map(|f| Value::String(f.clone()))
                    .collect(),
            ),
        );
        m.insert(
            "applied".to_owned(),
            Value::Array(
                self.applied
                    .iter()
                    .map(|a| Value::String(a.clone()))
                    .collect(),
            ),
        );
        m.insert(
            "decision".to_owned(),
            self.decision
                .as_ref()
                .map(effect_decision_to_payload)
                .unwrap_or(Value::Null),
        );
        m.insert("stdout".to_owned(), json!(self.stdout));
        m.insert("stderr".to_owned(), json!(self.stderr));
        m.insert(
            "proof".to_owned(),
            self.proof
                .as_ref()
                .map(|p| serde_json::to_value(p).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
        );
        m.insert("operation_id".to_owned(), json!(self.operation_id));
        m.insert("output_digest".to_owned(), json!(self.output_digest));
        Value::Object(m)
    }
}

// ===========================================================================
// Semantic workspace-write operations (contained_workspace_write_execution.py)
//
// `patch-check` / `patch-apply` / `format-write` / `copy-generated` are the
// caller-facing semantic ops. Unlike the token path, these resolve a real tool
// (`git`, `ruff`, `cp`) and run it inside the containment sandbox with the
// workspace-write scope narrowed to the declared target only — satisfying the
// Python isolation contract without snapshot staging.
// ===========================================================================

/// Python `ContainedWriteOperation` semantic literal.
const WW_SEMANTIC_OPS: &[&str] = &[
    "patch-check",
    "patch-apply",
    "format-write",
    "copy-generated",
];

/// `_resolve_executable` (:416-424): resolve `name` via `PATH` from the
/// scrubbed `environment`, pinned to a canonical regular executable file.
fn _resolve_executable(name: &str, env: &BTreeMap<String, String>) -> Result<PathBuf, String> {
    let path_var = env.get("PATH").cloned().unwrap_or_default();
    let mut found: Option<PathBuf> = None;
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            found = Some(candidate);
            break;
        }
    }
    let candidate = found.ok_or_else(|| format!("{name} executable unavailable"))?;
    let canonical = fs::canonicalize(&candidate)
        .map_err(|_| format!("{name} executable is not path-pinned"))?;
    let meta =
        fs::metadata(&canonical).map_err(|_| format!("{name} executable is not path-pinned"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(format!("{name} executable is not path-pinned"));
    }
    Ok(canonical)
}

fn _semantic_safe_relative(
    workspace: &Path,
    raw: &str,
    must_exist: bool,
) -> Result<PathBuf, String> {
    let rel = Path::new(raw);
    if raw.is_empty()
        || raw.contains('\\')
        || rel.is_absolute()
        || rel
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || rel
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join("/")
            != raw
    {
        return Err("workspace_path_not_canonical".to_owned());
    }
    const SEMANTIC_PROTECTED_NAMES: &[&str] = &[
        ".aws",
        ".claude",
        ".codex",
        ".cursor",
        ".docker",
        ".git",
        ".gnupg",
        ".guard",
        ".hol-guard",
        ".kube",
        ".ssh",
        "guard-home",
    ];
    if _is_protected_path(rel)
        || crate::harness_config_names::path_parts_protected(rel.components().filter_map(
            |component| match component {
                std::path::Component::Normal(part) => part.to_str(),
                _ => None,
            },
        ))
        || rel.components().any(|component| {
            let part = component.as_os_str().to_string_lossy().to_lowercase();
            part.starts_with(".env") || SEMANTIC_PROTECTED_NAMES.contains(&part.as_str())
        })
    {
        return Err("workspace_path_protected".to_owned());
    }
    if crate::shell_secret_read_support::classify_secret_path(raw, Some(workspace), None).is_some()
    {
        return Err("workspace_path_secret".to_owned());
    }
    let candidate = workspace.join(rel);
    let parent = candidate
        .parent()
        .ok_or_else(|| "workspace_path_not_canonical".to_owned())?;
    let canonical_parent = weak_canonicalize(parent);
    if !canonical_parent.starts_with(workspace) || !canonical_parent.is_dir() {
        return Err("workspace_path_escaped".to_owned());
    }
    let canonical = weak_canonicalize(&candidate);
    if !canonical.starts_with(workspace) {
        return Err("workspace_path_escaped".to_owned());
    }
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("workspace_path_symlink".to_owned());
            }
            if must_exist && (!metadata.is_file() || metadata.nlink() != 1) {
                return Err("workspace_input_not_regular".to_owned());
            }
            if must_exist && canonical != candidate {
                return Err("workspace_path_alias".to_owned());
            }
            if !must_exist && !metadata.is_file() {
                return Err("workspace_output_not_regular".to_owned());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
        Err(_) => return Err("workspace_input_not_regular".to_owned()),
    }
    Ok(candidate)
}

/// Build the tool argv the Python `_invocation()` produces per semantic op
/// (:300-349). Returns `(argv, target)`.
fn _semantic_tool_argv(
    operation: &str,
    source: &str,
    target: Option<&str>,
    workspace: &Path,
    env: &BTreeMap<String, String>,
) -> Result<(Vec<String>, Option<String>), String> {
    match operation {
        "patch-check" => {
            let patch = _semantic_safe_relative(workspace, source, true)?;
            let git = _resolve_executable("git", env)?;
            Ok((
                vec![
                    git.to_string_lossy().into_owned(),
                    "apply".to_owned(),
                    "--check".to_owned(),
                    "--".to_owned(),
                    patch.to_string_lossy().into_owned(),
                ],
                None,
            ))
        }
        "patch-apply" => {
            let target = target.ok_or_else(|| "patch-apply_requires_target".to_owned())?;
            let patch = _semantic_safe_relative(workspace, source, true)?;
            _semantic_safe_relative(workspace, target, false)?;
            let git = _resolve_executable("git", env)?;
            Ok((
                vec![
                    git.to_string_lossy().into_owned(),
                    "-C".to_owned(),
                    workspace.to_string_lossy().into_owned(),
                    "apply".to_owned(),
                    "--".to_owned(),
                    patch.to_string_lossy().into_owned(),
                ],
                Some(target.to_owned()),
            ))
        }
        "format-write" => {
            let target = target.ok_or_else(|| "format-write_requires_target".to_owned())?;
            let tgt = _semantic_safe_relative(workspace, target, true)?;
            let ruff = _resolve_executable("ruff", env)?;
            Ok((
                vec![
                    ruff.to_string_lossy().into_owned(),
                    "format".to_owned(),
                    "--no-cache".to_owned(),
                    tgt.to_string_lossy().into_owned(),
                ],
                Some(target.to_owned()),
            ))
        }
        "copy-generated" => {
            let target = target.ok_or_else(|| "copy-generated_requires_target".to_owned())?;
            let src = _semantic_safe_relative(workspace, source, true)?;
            let tgt = _semantic_safe_relative(workspace, target, false)?;
            let cp = _resolve_executable("cp", env)?;
            Ok((
                vec![
                    cp.to_string_lossy().into_owned(),
                    src.to_string_lossy().into_owned(),
                    tgt.to_string_lossy().into_owned(),
                ],
                Some(target.to_owned()),
            ))
        }
        other => Err(format!("unsupported_operation:{other}")),
    }
}

/// Structured semantic workspace-write execution — the honest port of
/// `contained_workspace_write_execution.py::try_execute_contained_workspace_write`
/// for the four semantic ops. The tool runs sandboxed with the write scope
/// narrowed to the declared target; `patch-check` is a dry-run (no write scope,
/// no promotion) and returns a result even on non-zero exit.
pub fn try_execute_contained_workspace_write_semantic(
    workspace: &Path,
    operation: &str,
    source: &str,
    target: Option<&str>,
    environment: Option<&BTreeMap<String, String>>,
    timeout_seconds: Option<u64>,
    guard_home: &Path,
) -> Option<ContainedWorkspaceWriteResult> {
    if !WW_SEMANTIC_OPS.contains(&operation) {
        return None;
    }
    let workspace = _canonical_directory(workspace).ok()?;
    _semantic_safe_relative(&workspace, source, true).ok()?;
    if let Some(raw_target) = target {
        _semantic_safe_relative(&workspace, raw_target, false).ok()?;
    }
    let run_id = format!("ww-semantic-{}", _now_epoch_ms());
    // Every operation, `patch-check` included, runs against a private stage that
    // holds only eligible files: protected content, symlinks and `.git` state
    // never reach the tool, and an ineligible workspace returns to review.
    let (stage, captured_workspace) =
        crate::semantic_workspace::stage_workspace(&workspace, guard_home, &run_id).ok()?;
    let execution_workspace = stage.0.canonicalize().ok()?;
    let mut env = environment.cloned().unwrap_or_default();
    let tool_path = crate::semantic_workspace::sanitize_tool_path(
        env.get("PATH").map(String::as_str),
        &[workspace.as_path(), execution_workspace.as_path()],
    );
    env.insert("PATH".to_owned(), tool_path);
    let (argv, target) =
        _semantic_tool_argv(operation, source, target, &execution_workspace, &env).ok()?;
    // A "write" op describing the declared target drives requirements + promote.
    let op_kind = match operation {
        "patch-apply" => "patch-apply",
        "format-write" => "format-write",
        "copy-generated" => "copy-generated",
        _ => "patch-check",
    };
    let ops: Vec<ContainedWriteOperation> = match &target {
        Some(t) => vec![ContainedWriteOperation {
            kind: "write".to_owned(),
            path: t.clone(),
            content: None,
            source: Some(source.to_owned()),
            mode: None,
        }],
        None => vec![],
    };
    let requirements = _requirements(&ops);
    // Narrow write scope to the declared target's parent dir (patch-check: none).
    let write_paths: Vec<String> = match &target {
        Some(t) => {
            let resolved = _semantic_safe_relative(&execution_workspace, t, false).ok()?;
            let parent = resolved
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or(execution_workspace.clone());
            vec![parent.to_string_lossy().into_owned()]
        }
        None => vec![],
    };
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "workspace-write".to_owned(),
        argv: argv.clone(),
        cwd: execution_workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: timeout_seconds.unwrap_or(60),
        max_output_bytes: 1024 * 1024,
        additional_read_paths: vec![execution_workspace.to_string_lossy().into_owned()],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        // `patch-check` is a dry run: a read-only policy with no write scope.
        action: if write_paths.is_empty() {
            ContainmentAction::Read
        } else {
            ContainmentAction::Write
        },
        workspace_read_paths: vec![execution_workspace.to_string_lossy().into_owned()],
        workspace_write_paths: write_paths,
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 8,
        max_open_files: 256,
        max_file_size_bytes: 8 * 1024 * 1024,
        max_write_bytes_total: 16 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 512,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let (exit_code, stdout_text, stderr_text, mut outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
    let staged_output = if exit_code == 0 && !ops.is_empty() {
        let op = ops.first()?;
        let staged_path = _semantic_safe_relative(&execution_workspace, &op.path, true).ok()?;
        let metadata = fs::symlink_metadata(&staged_path).ok()?;
        if !metadata.is_file() || metadata.size() > 8 * 1024 * 1024 {
            return None;
        }
        let content = fs::read(&staged_path).ok()?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
        outputs.push(ContainmentCapturedOutput {
            relative_path: op.path.clone(),
            sha256: digest.clone(),
            size_bytes: content.len() as u64,
            media_type: CAPTURED_OUTPUT_MEDIA_TYPE.to_owned(),
        });
        Some((op.path.clone(), digest))
    } else {
        None
    };
    let profile_digest = containment_profile_digest(&request, &policy, &enforcement);
    let attestation = ContainmentAttestation {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        enforcement: enforcement.clone(),
        profile_digest: profile_digest.clone(),
        started_epoch_ms: started_ms,
        exit_code,
        outputs: outputs.clone(),
        artifact_manifests: vec![],
    };
    // `patch-check` returns a result even on non-zero exit (dry-run veto); the
    // other ops treat non-zero as failure.
    let is_check = operation == "patch-check";
    if exit_code != 0 && !is_check {
        return Some(_result_without_promotion(attestation, outputs, captured));
    }
    let attestation_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            json!({
                "exit_code": exit_code,
                "outputs": outputs.iter().map(|o| &o.sha256).collect::<Vec<_>>(),
            })
            .to_string()
            .as_bytes(),
        ))
    );
    let health = load_current_containment_health(guard_home);
    let proof = contained_positive_proof(
        health.as_ref(),
        &enforcement,
        &profile_digest,
        &attestation_digest,
        &requirements,
    )
    .ok();
    let Some(proof) = proof else {
        return Some(_result_without_promotion(attestation, outputs, captured));
    };
    // Promotion requires the real workspace, target included, to be exactly what
    // was staged: a concurrent edit while the tool ran returns to review.
    if !ops.is_empty()
        && crate::semantic_workspace::capture_workspace(&workspace)
            .map_or(true, |current| current.digest != captured_workspace.digest)
    {
        return Some(_result_without_promotion(attestation, outputs, captured));
    }
    let mut applied: Vec<String> = Vec::new();
    for op in &ops {
        let Some((staged_output_path, expected_digest)) = staged_output.as_ref() else {
            return Some(_result_without_promotion(attestation, outputs, captured));
        };
        if staged_output_path != &op.path {
            return Some(_result_without_promotion(attestation, outputs, captured));
        }
        let staged_path = match _semantic_safe_relative(&execution_workspace, &op.path, true) {
            Ok(path) => path,
            Err(_) => return Some(_result_without_promotion(attestation, outputs, captured)),
        };
        match fs::symlink_metadata(&staged_path) {
            Ok(metadata) if metadata.is_file() && metadata.size() <= 8 * 1024 * 1024 => {}
            _ => return Some(_result_without_promotion(attestation, outputs, captured)),
        }
        let content = match fs::read(&staged_path) {
            Ok(content) => content,
            Err(_) => return Some(_result_without_promotion(attestation, outputs, captured)),
        };
        let current_digest = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
        if &current_digest != expected_digest {
            return Some(_result_without_promotion(attestation, outputs, captured));
        }
        let mut promotion = op.clone();
        promotion.content = Some(content);
        match _promote_output(&workspace, &promotion) {
            Ok(path) => applied.push(path),
            Err(_) => return Some(_result_without_promotion(attestation, outputs, captured)),
        }
    }
    let decision = _contained_decision(op_kind, proof.clone(), &requirements);
    Some(ContainedWorkspaceWriteResult {
        attestation,
        outputs,
        captured_files: captured,
        applied,
        decision,
        stdout: stdout_text,
        stderr: stderr_text,
        proof: Some(proof),
        operation_id: operation.to_owned(),
        output_digest: staged_output.map(|(_, digest)| digest),
    })
}

#[cfg(test)]
#[path = "contained_safe_relative_tests.rs"]
mod safe_relative_tests;
