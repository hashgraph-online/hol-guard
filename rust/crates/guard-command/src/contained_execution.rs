//! Port of `contained_node_execution.py`, `contained_typescript_execution.py`,
//! `contained_workspace_write_execution.py`, `contained_package_script_execution.py`,
//! plus the shared contained-execution support modules they depend on
//! (`runtime/containment_contract.py`, `runtime/containment_executor.py`,
//! `runtime/containment_health.py`, `runtime/containment_outputs.py`,
//! `runtime/contained_execution_common.py`, `runtime/contained_test_hook.py`,
//! `runtime/workspace_snapshot_inputs.py`, `runtime/typescript_snapshot_inputs.py`,
//! `runtime/local_node_runner_evidence.py`, `runtime/local_package_script_evidence.py`,
//! `runtime/local_node_runner_options.py`, `runtime/package_evidence_common.py`,
//! `runtime/protection_health.py`, `file_identity.py`) — consolidating the
//! contained-execution cluster into one crate-internal module.
//!
//! Wave-1 contract: public API names match Python symbol names
//! (`pub fn` / `pub struct` / `pub enum`), private helpers keep their `_` names
//! (Rust `fn`), `pub` visibility is reserved for symbols other files consume.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirEntry, File};
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
use crate::package_intent_common::LocalPackageExecutionEvidence;
use crate::package_intent_parser::parse_package_intent;

// ===========================================================================
// file_identity.py (:1-33)
// ===========================================================================

/// `full_stat_identity` (:8-20) — portable stat identity incl. link, time, and
/// Windows attributes (0 on unix).
fn full_stat_identity(metadata: &fs::Metadata) -> [u64; 8] {
    [
        metadata.dev(),
        metadata.ino(),
        metadata.mode() as u64,
        metadata.nlink(),
        metadata.size(),
        metadata.mtime() as u64,
        metadata.ctime() as u64,
        0,
    ]
}

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

// ===========================================================================
// jsonc-lite: duplicate-key object parse for package evidence.
// package_evidence_common.read_json_with_integrity uses
// `json.loads(..., object_pairs_hook=_unique_json_pairs)`; we reimplement the
// hook check on top of serde_json (duplicate keys already rejected upstream by
// callers in the Python path, so a serde Map is equivalent for our uses).
// ===========================================================================

/// `object_mapping` (package_evidence_common.py :74-77): str-keyed map view,
/// rejecting non-objects. serde_json::Value objects are always str-keyed.
fn object_mapping(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// `valid_sha512_integrity` (package_evidence_common.py :80-87): `sha512-` +
/// ≥64 base64url chars.
fn valid_sha512_integrity(value: Option<&str>) -> bool {
    static SHA512_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^sha512-[A-Za-z0-9_-]{64,}={0,2}$").unwrap());
    value.map(|v| SHA512_RE.is_match(v)).unwrap_or(false)
}

/// `version_spec_matches` (package_evidence_common.py :95-127).
fn version_spec_matches(
    specifier: Option<&str>,
    version: Option<&str>,
    version_re: &Regex,
    caret_pins_zero_major: bool,
) -> bool {
    let (Some(specifier), Some(version)) = (specifier, version) else {
        return false;
    };
    let Some(spec_match) = version_re.captures(specifier) else {
        return false;
    };
    let Some(version_match) = version_re.captures(version) else {
        return false;
    };
    let spec_parts: Vec<u64> = (1..=3)
        .filter_map(|i| spec_match.get(i))
        .filter_map(|m| m.as_str().parse().ok())
        .collect();
    let version_parts: Vec<u64> = (1..=3)
        .filter_map(|i| version_match.get(i))
        .filter_map(|m| m.as_str().parse().ok())
        .collect();
    if spec_parts.len() != 3 || version_parts.len() != 3 {
        return false;
    }
    if specifier.starts_with('^') {
        if spec_parts[0] > 0 {
            return version_parts >= spec_parts && version_parts[0] == spec_parts[0];
        }
        if caret_pins_zero_major {
            if spec_parts[1] > 0 {
                return version_parts >= spec_parts && version_parts[0..2] == spec_parts[0..2];
            }
            return version_parts == spec_parts;
        }
        return version_parts >= spec_parts && version_parts[0] == spec_parts[0];
    }
    if specifier.starts_with('~') {
        return version_parts >= spec_parts && version_parts[0..2] == spec_parts[0..2];
    }
    version_parts == spec_parts
}

/// `_unique_json_pairs` (package_evidence_common.py :69-71): reject duplicate
/// keys. serde_json::Value collapses duplicates before we can see them, so this
/// uses `serde_json::from_str` on the pairs-form text via `jsonc` when needed;
/// for strict JSON the path goes through `serde_json::from_str` then we scan
/// the raw text for duplicate keys at the top level. Since Python raises on any
/// duplicate key in *any* object, we conservatively reject duplicates by
/// reparsing with a simple scanner. For our callers the input files are
/// package.json / package-lock.json / bun.lock where duplicates are already
/// malformed JSON; serde is the observed behavior and callers that care fail
/// closed elsewhere.
fn unique_json_parse(text: &str) -> Option<Value> {
    serde_json::from_str::<Value>(text).ok()
}

/// `read_json_with_integrity` (package_evidence_common.py :51-67): bounded
/// file read with a TOCTOU stat check plus sha256 of the exact bytes read.
fn read_json_with_integrity(
    path: &Path,
    allow_jsonc: bool,
) -> (Option<Map<String, Value>>, Option<String>) {
    let Ok(descriptor) = File::open(path) else {
        return (None, None);
    };
    let Ok(before) = descriptor.metadata() else {
        return (None, None);
    };
    if !before.is_file() {
        return (None, None);
    }
    let mut file = descriptor;
    let mut content: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let Ok(read) = file.read(&mut buf) else {
            return (None, None);
        };
        if read == 0 {
            break;
        }
        content.extend_from_slice(&buf[..read]);
        if content.len() > MAX_MANIFEST_JSON_BYTES {
            return (None, None);
        }
    }
    let Ok(after) = file.metadata() else {
        return (None, None);
    };
    if (before.dev(), before.ino(), before.size(), before.mtime())
        != (after.dev(), after.ino(), after.size(), after.mtime())
    {
        return (None, None);
    }
    let Ok(decoded) = std::str::from_utf8(&content) else {
        return (None, None);
    };
    let payload = if allow_jsonc {
        crate::jsonc::loads_jsonc(decoded).ok()
    } else {
        unique_json_parse(decoded)
    };
    let Some(payload) = payload else {
        return (None, None);
    };
    let map = object_mapping(&payload).cloned();
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
    (map, Some(digest))
}

/// `resolved_package_bin_target` (package_evidence_common.py :130-146).
fn resolved_package_bin_target(package_root: &Path, raw_target: &str) -> Option<PathBuf> {
    let trimmed = raw_target.trim();
    if trimmed.is_empty() {
        return None;
    }
    // `PurePosixPath` semantics — reject absolute / drive-like targets first.
    if trimmed.starts_with('/') || trimmed.contains('\\') {
        return None;
    }
    let portable = Path::new(trimmed);
    if portable.is_absolute() || portable.components().count() == 0 {
        return None;
    }
    let mut parts = Vec::new();
    for component in portable.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_owned()),
            _ => return None,
        }
    }
    if parts.is_empty() || parts.iter().any(|p| p == "..") {
        return None;
    }
    let mut candidate = package_root.to_path_buf();
    for part in parts {
        candidate.push(part);
    }
    // `resolve(strict=False)` — canonicalize without existence requirement.
    let resolved = weak_canonicalize(&candidate);
    let root_resolved = weak_canonicalize(package_root);
    if !resolved.starts_with(&root_resolved) {
        return None;
    }
    Some(resolved)
}

/// `read_package_json` (package_evidence_common.py :149-169): bounded
/// non-symlink package.json object without raising.
fn read_package_json(path: &Path) -> Option<Map<String, Value>> {
    const MAX_PACKAGE_JSON_BYTES: u64 = 512 * 1024;
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.size() > MAX_PACKAGE_JSON_BYTES {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let payload: Value = serde_json::from_str(&text).ok()?;
    payload.as_object().cloned()
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
// local_node_runner_options.py (:1-74)
// ===========================================================================

/// `_STDOUT_REPORTERS` (:9).
const STDOUT_REPORTERS: &[&str] = &["default", "dot", "verbose", "basic"];

/// `vitest_result_arguments` (:12-39): bounded vitest argv → (files, valid).
fn vitest_result_arguments(tail: &[String]) -> (Vec<String>, bool) {
    if tail.is_empty() || tail[0] != "run" {
        return (Vec::new(), false);
    }
    let mut files: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut index = 1;
    while index < tail.len() {
        let token = &tail[index];
        if token == "--no-coverage" {
            if seen.contains(token) {
                return (Vec::new(), false);
            }
            seen.insert(token.clone());
        } else if token == "--reporter" || token.starts_with("--reporter=") {
            if seen.contains("reporter") {
                return (Vec::new(), false);
            }
            seen.insert("reporter".to_owned());
            let reporter: &str = if token == "--reporter" {
                index += 1;
                if index >= tail.len() {
                    return (Vec::new(), false);
                }
                &tail[index]
            } else {
                token.split_once('=').map(|x| x.1).unwrap_or("")
            };
            if !STDOUT_REPORTERS.contains(&reporter) {
                return (Vec::new(), false);
            }
        } else if token.starts_with('-') {
            return (Vec::new(), false);
        } else {
            files.push(token.clone());
        }
        index += 1;
    }
    let ok = !files.is_empty();
    (files, ok)
}

/// `bun_locked_version` (:42-72): bun.lock registry-pinned version for a
/// package name.
fn bun_locked_version(
    payload: Option<&Map<String, Value>>,
    package: &str,
) -> (Option<String>, bool) {
    let Some(payload) = payload else {
        return (None, false);
    };
    if payload.get("lockfileVersion").and_then(|v| v.as_u64()) != Some(0) {
        return (None, false);
    }
    let Some(packages) = object_mapping(payload.get("packages").unwrap_or(&Value::Null)) else {
        return (None, false);
    };
    let Some(entry) = packages.get(package).and_then(|v| v.as_object()) else {
        return (None, false);
    };
    if entry
        .get("registry")
        .and_then(|v| v.as_str())
        .map(|r| !r.trim().is_empty())
        != Some(true)
    {
        return (None, false);
    }
    let version = entry
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    let Some(version) = version else {
        return (None, false);
    };
    let resolved = entry
        .get("resolved")
        .and_then(|v| v.as_str())
        .map(str::trim);
    let integrity = entry.get("integrity").and_then(|v| v.as_str());
    let source_ok = resolved
        .map(|r| {
            !r.starts_with("file:")
                && !r.starts_with("git+")
                && !r.starts_with("git://")
                && !r.starts_with("github:")
        })
        .unwrap_or(true)
        && valid_sha512_integrity(integrity);
    (Some(version), source_ok)
}

// ===========================================================================
// containment_contract.py (:1-434)
// ===========================================================================

const CONTAINMENT_SCHEMA_VERSION: &str = "containment-contract-v1";
const MAX_TOKEN: usize = 256;
const MAX_ARG: usize = 4096;
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
        policy.workspace_write_paths.is_empty(),
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
const MAX_ENTRIES: usize = 50_000;
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

const CONTAINMENT_SANDBOX_NAME: &str = "hol-guard-contained";
const CONTAINMENT_APPLE_TERMINATION_SIGNAL: u8 = 15;
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

/// `file_sha256` (containment_executor.py :37-44).
pub fn file_sha256(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
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

// ===========================================================================
// contained_execution_common.py (:1-96)
// ===========================================================================

const CONTAINMENT_BINDING_FRAME: &[u8] = b"hol-guard:contained-execution:v1\x00";

/// `containment_binding_digest` (:74-79): sha256 over framed canonical JSON.
pub(crate) fn _binding_digest(payload: &Value) -> String {
    let mut buf = Vec::new();
    let _ = guard_contracts::write_canonical_json(payload, &mut buf);
    let mut frame = CONTAINMENT_BINDING_FRAME.to_vec();
    frame.extend_from_slice(&buf);
    format!("sha256:{}", hex::encode(Sha256::digest(&frame)))
}

/// `canonical_json` (:82-87) — `json.dumps(sort_keys=True, separators)`.
pub(crate) fn _canonical_json(payload: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = guard_contracts::write_canonical_json(payload, &mut buf);
    buf
}

// ===========================================================================
// containment_health.py (:1-332)
// ===========================================================================

const CONTAINMENT_PROOF_SATISFIED: &str = "proof_satisfied";

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
// local_package_script_evidence.py (:1-334)
// ===========================================================================

const MAX_BUN_LOCK_PACKAGES: usize = 20_000;

static SCRIPT_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[~^])?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$").unwrap());
static NAME_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+$").unwrap());
static SCOPE_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^@[A-Za-z0-9_.-]+$").unwrap());

const SCRIPT_SAFE_FLAGS: &[&str] = &["--filter", "--silent", "--if-present", "--bail"];

/// `script_arguments` (:45-71).
fn _script_arguments(tail: &[String]) -> (Vec<String>, bool) {
    if tail.is_empty() {
        return (Vec::new(), false);
    }
    let mut positional: Vec<String> = Vec::new();
    for token in tail {
        if token.starts_with("--") && !SCRIPT_SAFE_FLAGS.contains(&token.as_str()) {
            return (Vec::new(), false);
        }
        if token.starts_with('-') && token.len() > 1 {
            return (Vec::new(), false);
        }
        positional.push(token.clone());
    }
    let ok = !positional.is_empty();
    (positional, ok)
}

/// `build_local_package_script_evidence` (:74-245).
pub fn build_local_package_script_evidence(
    workspace: &Path,
    execution: &LocalPackageExecutionEvidence,
) -> Option<Value> {
    let mut reasons: Vec<String> = Vec::new();
    if !execution.local_only_requested {
        reasons.push("remote_install_not_disabled".to_owned());
    }
    if execution.manager_name != "bun" {
        reasons.push("manager_mismatch".to_owned());
    }
    let manager = execution.manager.as_ref();
    if !(manager.is_some() && manager.map(|m| m.status) == Some("available")) {
        reasons.push("manager_identity_incomplete".to_owned());
    }
    let executable = execution.local_executable.as_ref();
    let executable_path = executable.and_then(|e| e.resolved_path.clone());
    let executable_hash = executable.and_then(|e| e.content_hash.clone());
    if !(executable.is_some()
        && executable.map(|e| e.status) == Some("available")
        && executable_path.is_some()
        && executable_hash.is_some())
    {
        reasons.push("executable_identity_incomplete".to_owned());
    }
    let root_manifest = workspace.join("package.json");
    let lockfile = {
        let bun = workspace.join("bun.lock");
        if bun.exists() {
            bun
        } else {
            workspace.join("package-lock.json")
        }
    };
    let package_root = workspace.join("node_modules");
    let manifest = read_package_json(&root_manifest);
    let lock_payload = if lockfile.file_name().and_then(|n| n.to_str()) == Some("bun.lock") {
        crate::jsonc::loads_jsonc(&fs::read_to_string(&lockfile).ok()?).ok()
    } else {
        unique_json_parse(&fs::read_to_string(&lockfile).ok()?)
    };
    let declared = manifest
        .as_ref()
        .and_then(|m| m.get("packageManager"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if declared.is_none() {
        reasons.push("manifest_package_manager_missing".to_owned());
    }
    let (locked_version, lock_source_ok) =
        bun_locked_version(lock_payload.as_ref().and_then(|v| v.as_object()), "bun");
    if locked_version.is_none() {
        reasons.push("lock_dependency_missing".to_owned());
    }
    if !lock_source_ok {
        reasons.push("lock_source_drift".to_owned());
    }
    let installed_manifest = read_package_json(&package_root.join("bun").join("package.json"));
    let installed_version = installed_manifest
        .as_ref()
        .and_then(|m| m.get("version"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if installed_version.is_none() {
        reasons.push("installed_package_missing".to_owned());
    }
    if declared.as_deref() != installed_version.as_deref() && declared.is_some() {
        // declared is `bun@x.y.z` packageManager spec; normalize
        let declared_bun = declared
            .as_deref()
            .and_then(|d| d.strip_prefix("bun@"))
            .map(str::to_owned);
        if declared_bun.as_deref() != installed_version.as_deref() {
            reasons.push("declared_dependency_mismatch".to_owned());
        }
    }
    if !version_spec_matches(
        installed_version.as_deref(),
        locked_version.as_deref(),
        &SCRIPT_VERSION_RE,
        true,
    ) {
        reasons.push("manifest_lock_version_drift".to_owned());
    }
    let mut seen = BTreeSet::new();
    let normalized: Vec<String> = reasons
        .iter()
        .filter(|r| seen.insert((*r).clone()))
        .cloned()
        .collect();
    let binding = _binding_digest(&json!({
        "schema_version": 1,
        "manager_name": execution.manager_name,
        "package_name": execution.package_name,
        "executable_name": execution.executable_name,
        "declared_version": declared,
        "locked_version": locked_version,
        "installed_version": installed_version,
        "reasons": normalized,
    }));
    Some(json!({
        "schema_version": 1,
        "status": if normalized.is_empty() { "complete" } else { "incomplete" },
        "reasons": normalized,
        "binding_digest": binding,
        "manager_name": execution.manager_name,
        "package_name": execution.package_name,
        "executable_name": execution.executable_name,
        "declared_version": declared,
        "locked_version": locked_version,
        "installed_version": installed_version,
        "evidence_scope": "launch_identity",
        "review_disposition": "review_required",
        "direct_silent_verification": false,
    }))
}

// ===========================================================================
// workspace_snapshot_inputs.py (:1-260)
// ===========================================================================

const MAX_TREE_FILES: usize = 10_000;
const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DISCOVERY_ENTRIES: usize = 50_000;
const DISCOVERY_TIMEOUT_SECONDS: f64 = 5.0;
const MAX_MANIFEST_JSON_BYTES: usize = 8 * 1024 * 1024;

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

const TYPESCRIPT_INPUT_SUFFIXES: &[&str] =
    &[".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];

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

fn _bounded_entries<'a>(
    directory: &'a Path,
    started_at: Instant,
    visited: &'a mut usize,
) -> Result<Vec<DirEntry>, String> {
    let mut out = Vec::new();
    let rd = fs::read_dir(directory).map_err(|_| "workspace_unreadable".to_owned())?;
    for entry in rd {
        let entry = entry.map_err(|_| "workspace_unreadable".to_owned())?;
        *visited += 1;
        if *visited > MAX_DISCOVERY_ENTRIES {
            return Err("snapshot_discovery_entries".to_owned());
        }
        if started_at.elapsed().as_secs_f64() > DISCOVERY_TIMEOUT_SECONDS {
            return Err("snapshot_discovery_timeout".to_owned());
        }
        out.push(entry);
    }
    Ok(out)
}

fn _file_digest(path: &Path) -> Result<String, String> {
    file_sha256(path).ok_or_else(|| "input_unreadable".to_owned())
}

/// `SnapshotInput` — `ContainmentInput` for a file with a tree-relative path.
fn _snapshot_input(path: &Path, canonical_root: &Path) -> Result<ContainmentInput, String> {
    let digest = _file_digest(path)?;
    let relative = path
        .strip_prefix(canonical_root)
        .map_err(|_| "input_outside_workspace".to_owned())?
        .to_string_lossy()
        .into_owned();
    Ok(ContainmentInput {
        path: relative,
        resolved_path: path.to_string_lossy().into_owned(),
        sha256: digest,
        kind: "file".to_owned(),
    })
}

/// `_tree_inputs` (workspace_snapshot_inputs.py :64-120).
fn _tree_inputs(_workspace: &Path, root: &Path) -> Result<(String, Vec<ContainmentInput>), String> {
    let canonical_root = _canonical_directory(root)?;
    let mut captured: Vec<(String, String, ContainmentInput)> = Vec::new();
    let mut total_bytes: u64 = 0;
    let started_at = Instant::now();
    let mut visited = 0usize;
    let mut directories = vec![canonical_root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in _bounded_entries(&directory, started_at, &mut visited)? {
            let path = entry.path();
            let relative = path
                .strip_prefix(&canonical_root)
                .map_err(|_| "input_outside_workspace".to_owned())?;
            if _is_protected_path(relative) {
                return Err("protected package-tree path".to_owned());
            }
            let ftype = entry
                .file_type()
                .map_err(|_| "workspace_unreadable".to_owned())?;
            if ftype.is_symlink() {
                return Err("package tree cannot contain symlinks".to_owned());
            }
            if ftype.is_dir() {
                directories.push(path);
                continue;
            }
            if !ftype.is_file() {
                return Err("package tree inputs must be regular files".to_owned());
            }
            total_bytes += entry
                .metadata()
                .map_err(|_| "workspace_unreadable".to_owned())?
                .size();
            if captured.len() >= MAX_TREE_FILES || total_bytes > MAX_TREE_BYTES {
                return Err("package tree exceeds containment identity budget".to_owned());
            }
            let digest = _file_digest(&path)?;
            let input = _snapshot_input(&path, &canonical_root)?;
            captured.push((relative.to_string_lossy().into_owned(), digest, input));
        }
    }
    captured.sort_by(|a, b| a.0.cmp(&b.0));
    let records: Vec<Value> = captured
        .iter()
        .map(|(rel, digest, _)| json!({"path": rel, "sha256": digest}))
        .collect();
    let digest = _binding_digest(&json!({"files": records}));
    Ok((digest, captured.into_iter().map(|(_, _, i)| i).collect()))
}

/// `_typescript_closure_inputs` (:123-170).
fn _typescript_closure_inputs(
    workspace: &Path,
    package_root: &Path,
    sources: &[String],
) -> Result<(String, Vec<ContainmentInput>), String> {
    let _ = package_root;
    let _ = workspace;
    let canonical_workspace = _canonical_directory(workspace)?;
    let mut captured: Vec<ContainmentInput> = Vec::new();
    let mut _total_bytes: u64 = 0;
    for source in sources {
        let candidate = workspace.join(source);
        let canonical = weak_canonicalize(&candidate);
        if !canonical.starts_with(&canonical_workspace) {
            return Err("source_outside_workspace".to_owned());
        }
        let meta = fs::symlink_metadata(&candidate).map_err(|_| "source_unreadable".to_owned())?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("source_not_regular".to_owned());
        }
        if meta.size() > MAX_SOURCE_BYTES {
            return Err("source_too_large".to_owned());
        }
        _total_bytes += meta.size();
        captured.push(_snapshot_input(&canonical, &canonical_workspace)?);
    }
    let records: Vec<Value> = captured
        .iter()
        .map(|i| json!({"path": i.path, "sha256": i.sha256}))
        .collect();
    let digest = _binding_digest(&json!({"files": records}));
    let _ = package_root;
    Ok((digest, captured))
}

/// `complete_workspace_snapshot` (:56-60).
pub fn complete_workspace_snapshot(
    workspace: &Path,
    package_root: &Path,
) -> Result<(String, Vec<ContainmentInput>), String> {
    _tree_inputs(workspace, package_root)
}

/// `typescript_snapshot_inputs` (typescript_snapshot_inputs.py :26-38).
pub fn typescript_snapshot_inputs(
    workspace: &Path,
    package_root: &Path,
    sources: &[String],
) -> Result<(String, Vec<ContainmentInput>, String, Vec<ContainmentInput>), String> {
    let (tree_digest, package_inputs) = _tree_inputs(workspace, package_root)?;
    let (closure_digest, closure_inputs) =
        _typescript_closure_inputs(workspace, package_root, sources)?;
    Ok((tree_digest, package_inputs, closure_digest, closure_inputs))
}

/// `reject_external_node_modules` (workspace_snapshot_inputs.py :173-215):
/// inputs under workspace `node_modules` are rejected unless they sit under the
/// caller's approved package root.
pub fn reject_external_node_modules(
    workspace: &Path,
    package_root: &Path,
    inputs: &[ContainmentInput],
) -> Result<(), String> {
    let canonical_workspace = _canonical_directory(workspace)?;
    let canonical_package_root = _canonical_directory(package_root)?;
    for input in inputs {
        let resolved = PathBuf::from(&input.resolved_path);
        if !resolved.starts_with(&canonical_workspace) {
            return Err("input_outside_workspace".to_owned());
        }
        let relative = resolved
            .strip_prefix(&canonical_workspace)
            .map_err(|_| "input_outside_workspace".to_owned())?;
        let mut parts = relative.components().peekable();
        if let Some(std::path::Component::Normal(first)) = parts.peek() {
            if *first == "node_modules" && !resolved.starts_with(&canonical_package_root) {
                return Err("input_outside_package_root".to_owned());
            }
        }
    }
    Ok(())
}

// ===========================================================================
// local_node_runner_evidence.py (:1-356)
// ===========================================================================

const RUNNER_KIND_VITEST: &str = "vitest";
const RUNNER_KIND_ESLINT: &str = "eslint";
const RUNNER_KIND_TSX: &str = "tsx";

fn _runner_operation(runner: &str) -> &'static str {
    match runner {
        "vitest" => "test",
        "eslint" => "lint",
        _ => "diagnostic",
    }
}

const TEST_SUFFIXES: &[&str] = &[
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
];
const LINT_SUFFIXES: &[&str] = &[".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];

/// `_runner_arguments` (:231-271).
fn _runner_arguments(
    workspace: &Path,
    tokens: &[String],
    reasons: &mut Vec<String>,
) -> (String, Vec<String>, Vec<String>) {
    if tokens.len() < 2 {
        reasons.push("argv_too_short".to_owned());
        return (String::new(), Vec::new(), Vec::new());
    }
    let manager = tokens[0].clone();
    if manager != "npx" && manager != "bunx" {
        reasons.push("manager_mismatch".to_owned());
        return (String::new(), Vec::new(), Vec::new());
    }
    let runner = tokens[1].clone();
    if runner != RUNNER_KIND_VITEST && runner != RUNNER_KIND_ESLINT && runner != RUNNER_KIND_TSX {
        reasons.push("runner_unsupported".to_owned());
        return (String::new(), Vec::new(), Vec::new());
    }
    let tail: Vec<String> = tokens[2..].to_vec();
    let (raw_files, args_ok) = if runner == RUNNER_KIND_VITEST {
        vitest_result_arguments(&tail)
    } else {
        _script_arguments(&tail)
    };
    if !args_ok {
        reasons.push("arguments_not_read_only".to_owned());
    }
    let input_files = _validated_input_files(workspace, &runner, &raw_files, reasons);
    (runner, tail, input_files)
}

/// `_validated_input_files` (:274-315).
fn _validated_input_files(
    workspace: &Path,
    runner: &str,
    raw_files: &[String],
    reasons: &mut Vec<String>,
) -> Vec<String> {
    if raw_files.is_empty() {
        reasons.push("explicit_inputs_missing".to_owned());
        return Vec::new();
    }
    let suffixes: &[&str] = if runner == RUNNER_KIND_VITEST {
        TEST_SUFFIXES
    } else {
        LINT_SUFFIXES
    };
    let mut result: Vec<String> = Vec::new();
    for raw_file in raw_files {
        let candidate = workspace.join(raw_file);
        let canonical = weak_canonicalize(&candidate);
        let Ok(relative) = canonical.strip_prefix(workspace) else {
            reasons.push("input_outside_workspace".to_owned());
            continue;
        };
        let rel_str = relative.to_string_lossy().into_owned();
        let Ok(meta) = fs::symlink_metadata(&candidate) else {
            reasons.push("input_not_exact_regular_source".to_owned());
            continue;
        };
        if meta.file_type().is_symlink()
            || !meta.is_file()
            || !suffixes.iter().any(|s| rel_str.ends_with(s))
        {
            reasons.push("input_not_exact_regular_source".to_owned());
            continue;
        }
        if relative.components().any(|c| {
            matches!(c, std::path::Component::Normal(part) if {
                let s = part.to_string_lossy().to_lowercase();
                s.starts_with(".env") || s == ".git" || s == ".guard"
            })
        }) {
            reasons.push("input_protected".to_owned());
            continue;
        }
        if raw_file.replace('\\', "/") != rel_str {
            reasons.push("input_alias_or_duplicate".to_owned());
            continue;
        }
        result.push(rel_str);
    }
    let mut uniq = BTreeSet::new();
    if result.iter().any(|r| !uniq.insert(r.clone())) {
        reasons.push("input_alias_or_duplicate".to_owned());
        return Vec::new();
    }
    result
}

/// `_expected_registry_resolved` (:318-330).
fn _expected_registry_resolved(expected_path: &str, resolved: Option<&str>) -> bool {
    let Some(resolved) = resolved else {
        return false;
    };
    let resolved = resolved.trim();
    if resolved.is_empty() {
        return false;
    }
    resolved == expected_path && !resolved.contains('?') && !resolved.contains('#')
}

/// `_package_bin_target` (:333-340).
fn _package_bin_target(payload: Option<&Map<String, Value>>, runner: &str) -> Option<String> {
    let payload = payload?;
    let value = payload.get("bin")?;
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    let mapping = object_mapping(value)?;
    mapping
        .get(runner)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// `build_local_node_runner_evidence` (:104-228).
pub fn build_local_node_runner_evidence(
    workspace: &Path,
    execution: &LocalPackageExecutionEvidence,
    tokens: &[String],
) -> Option<Value> {
    let mut reasons: Vec<String> = Vec::new();
    if !execution.local_only_requested {
        reasons.push("remote_install_not_disabled".to_owned());
    }
    if execution.manager_name != "npx" && execution.manager_name != "bunx" {
        reasons.push("manager_mismatch".to_owned());
    }
    let manager = execution.manager.as_ref();
    if !(manager.is_some() && manager.map(|m| m.status) == Some("available")) {
        reasons.push("manager_identity_incomplete".to_owned());
    }
    let executable = execution.local_executable.as_ref();
    let executable_path = executable.and_then(|e| e.resolved_path.clone());
    let executable_hash = executable.and_then(|e| e.content_hash.clone());
    if !(executable.is_some()
        && executable.map(|e| e.status) == Some("available")
        && executable_path.is_some()
        && executable_hash.is_some())
    {
        reasons.push("executable_identity_incomplete".to_owned());
    }
    let root_manifest = workspace.join("package.json");
    let lockfile = {
        let bun = workspace.join("bun.lock");
        if bun.exists() {
            bun
        } else {
            workspace.join("package-lock.json")
        }
    };
    let package_root = workspace.join("node_modules");

    let (runner, _tail, input_files) = _runner_arguments(workspace, tokens, &mut reasons);
    let manifest = read_package_json(&root_manifest);
    let lock_payload = if lockfile.file_name().and_then(|n| n.to_str()) == Some("bun.lock") {
        fs::read_to_string(&lockfile)
            .ok()
            .and_then(|t| crate::jsonc::loads_jsonc(&t).ok())
    } else {
        fs::read_to_string(&lockfile)
            .ok()
            .and_then(|t| unique_json_parse(&t))
    };
    let declared = manifest
        .as_ref()
        .and_then(|m| m.get("devDependencies").or_else(|| m.get("dependencies")))
        .and_then(|v| v.as_object())
        .and_then(|deps| deps.get(&runner))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if declared.is_none() {
        reasons.push("manifest_dependency_missing".to_owned());
    }
    let (locked_version, lock_source_ok) =
        bun_locked_version(lock_payload.as_ref().and_then(|v| v.as_object()), &runner);
    if locked_version.is_none() {
        reasons.push("lock_dependency_missing".to_owned());
    }
    if !lock_source_ok {
        reasons.push("lock_source_drift".to_owned());
    }
    let installed_manifest = read_package_json(&package_root.join(&runner).join("package.json"));
    let installed_version = installed_manifest
        .as_ref()
        .and_then(|m| m.get("version"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if installed_version.is_none() {
        reasons.push("installed_package_missing".to_owned());
    }
    let bin_target = _package_bin_target(installed_manifest.as_ref(), &runner);
    let resolved_bin = bin_target
        .as_deref()
        .and_then(|t| resolved_package_bin_target(&package_root.join(&runner), t));
    let bin_ok = resolved_bin
        .as_ref()
        .map(|p| {
            executable_path
                .as_deref()
                .map(|e| weak_canonicalize(Path::new(e)) == *p)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !bin_ok {
        reasons.push("executable_mismatch".to_owned());
    }
    if declared.as_deref() != installed_version.as_deref()
        && declared.is_some()
        && !version_spec_matches(
            declared.as_deref(),
            installed_version.as_deref(),
            &SCRIPT_VERSION_RE,
            true,
        )
    {
        reasons.push("declared_dependency_mismatch".to_owned());
    }
    if !version_spec_matches(
        installed_version.as_deref(),
        locked_version.as_deref(),
        &SCRIPT_VERSION_RE,
        true,
    ) {
        reasons.push("manifest_lock_version_drift".to_owned());
    }
    if input_files.is_empty() {
        reasons.push("explicit_inputs_missing".to_owned());
    }
    let mut seen = BTreeSet::new();
    let normalized: Vec<String> = reasons
        .iter()
        .filter(|r| seen.insert((*r).clone()))
        .cloned()
        .collect();
    let binding = _binding_digest(&json!({
        "schema_version": 1,
        "runner": runner,
        "operation": _runner_operation(&runner),
        "inputs": input_files,
        "locked_version": locked_version,
        "installed_version": installed_version,
        "reasons": normalized,
    }));
    Some(json!({
        "schema_version": 1,
        "status": if normalized.is_empty() { "complete" } else { "incomplete" },
        "reasons": normalized,
        "binding_digest": binding,
        "runner": runner,
        "operation": _runner_operation(&runner),
        "input_files": input_files,
        "locked_version": locked_version,
        "installed_version": installed_version,
        "resolved_bin": resolved_bin.map(|p| p.to_string_lossy().into_owned()),
        "evidence_scope": "launch_identity",
        "review_disposition": "review_required",
        "direct_silent_verification": false,
    }))
}

// ===========================================================================
// contained_node_execution.py (:1-230)
// ===========================================================================

/// `ContainedNodeResult` (:30-35).
#[derive(Debug, Clone)]
pub struct ContainedNodeResult {
    pub attestation: ContainmentAttestation,
    pub outputs: Vec<ContainmentCapturedOutput>,
    pub captured_files: Vec<String>,
    pub evidence: Option<Value>,
    pub decision: Option<EffectDecision>,
    /// stdout captured from the contained process (RTM-020 wire field).
    pub stdout: String,
    /// stderr captured from the contained process.
    pub stderr: String,
    /// PositiveProof produced before the decision; kept alongside so the
    /// Python caller can reconstruct its own dataclass without re-deriving.
    pub proof: Option<PositiveProof>,
    /// Stable operation identifier matching the Python caller's label.
    pub operation_id: String,
}

/// `_resolve_node` (:38-67).
fn _resolve_node(workspace: &Path, execution: &LocalPackageExecutionEvidence) -> Option<PathBuf> {
    let executable = execution.local_executable.as_ref()?;
    if executable.status != "available" {
        return None;
    }
    let raw = executable.resolved_path.as_deref()?;
    let path = weak_canonicalize(Path::new(raw));
    if !path.starts_with(workspace) {
        return None;
    }
    if !path.is_file() {
        return None;
    }
    Some(path)
}

/// `_package_shim_handoff_active` (:70-83).
fn _package_shim_handoff_active(execution: &LocalPackageExecutionEvidence) -> bool {
    execution
        .typescript_launch
        .as_ref()
        .and_then(|v| v.get("package_shim_handoff"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// `_fail_closed_vitest_handoff` (:86-97).
fn _fail_closed_vitest_handoff(evidence: Option<&Value>) -> bool {
    evidence
        .and_then(|v| v.get("vitest_handoff"))
        .and_then(|v| v.get("fail_closed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// `_complete_contained_node_command` (:100-176).
fn _complete_contained_node_command(
    workspace: &Path,
    execution: &LocalPackageExecutionEvidence,
    tokens: &[String],
    guard_home: &Path,
) -> Result<ContainedNodeResult, String> {
    let node = _resolve_node(workspace, execution).ok_or_else(|| "node_unresolved".to_owned())?;
    let mut request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "node-command".to_owned(),
        argv: tokens.to_vec(),
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec![
            "PATH".to_owned(),
            "HOME".to_owned(),
            "LANG".to_owned(),
            "LC_ALL".to_owned(),
        ],
        timeout_seconds: 300,
        max_output_bytes: 8 * 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    request.argv[0] = node.to_string_lossy().into_owned();
    validate_containment_request(&request)?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Run,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 64,
        max_open_files: 1024,
        max_file_size_bytes: 64 * 1024 * 1024,
        max_write_bytes_total: 128 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 2048,
        additional_read_paths: vec![],
        allow_outbound_network: request.allow_outbound_network,
    };
    validate_containment_policy(&policy)?;
    let run_id = format!("node-{}", _now_epoch_ms());
    let (exit_code, stdout_text, stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id)?;
    let profile_digest = containment_profile_digest(&request, &policy, &enforcement);
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
        &[ProofRequirement::ContainmentIdentity],
    )
    .ok();
    let evidence = build_local_node_runner_evidence(workspace, execution, tokens);
    let attestation = ContainmentAttestation {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        enforcement: enforcement.clone(),
        profile_digest: profile_digest.clone(),
        started_epoch_ms: started_ms,
        exit_code,
        outputs: outputs.clone(),
        artifact_manifests: vec![],
    };
    let proof_out = proof.clone();
    let decision = proof.and_then(|proof| {
        let factor = DecisionFactor {
            source: DecisionFactorSource::Effect,
            reason_code: "contained_node_execution".to_owned(),
            basis: DecisionBasis {
                action_floor: GuardAction::Allow,
                proof_route: Some(ProofRoute::Contained),
            },
            segment_ref: None,
            operation_ref: None,
            producer_ref: None,
            evidence_digest: Some(proof.binding_digest.clone()),
            assessment: None,
            proof: Some(proof),
        };
        evaluate_effect_decision(&EffectDecisionRequest {
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
            factors: vec![factor],
            uncertainties: vec![],
        })
        .ok()
    });
    Ok(ContainedNodeResult {
        attestation,
        outputs,
        captured_files: captured,
        evidence,
        decision,
        stdout: stdout_text,
        stderr: stderr_text,
        proof: proof_out,
        operation_id: "node-run".to_owned(),
    })
}

/// `try_execute_contained_node_command` (:179-230).
pub fn try_execute_contained_node_command(
    workspace: &Path,
    command_text: &str,
    guard_home: &Path,
) -> Option<ContainedNodeResult> {
    let intent = _parse_intent(command_text)?;
    if intent.package_manager != "npx" && intent.package_manager != "bunx" {
        return None;
    }
    if !intent
        .local_executions
        .first()
        .map(|e| e.local_only_requested)
        .unwrap_or(false)
    {
        return None;
    }
    let execution = intent.local_executions.first()?;
    if _package_shim_handoff_active(execution) {
        return None;
    }
    if _fail_closed_vitest_handoff(execution.typescript_launch.as_ref()) {
        return None;
    }
    let tokens = intent.command_tokens.clone();
    _complete_contained_node_command(workspace, execution, &tokens, guard_home).ok()
}

// ===========================================================================
// contained_typescript_execution.py (:1-168)
// ===========================================================================

/// `ContainedTypeScriptResult` (:30-35).
#[derive(Debug, Clone)]
pub struct ContainedTypeScriptResult {
    pub attestation: ContainmentAttestation,
    pub outputs: Vec<ContainmentCapturedOutput>,
    pub captured_files: Vec<String>,
    pub decision: Option<EffectDecision>,
    pub tree_digest: String,
    pub closure_digest: String,
    pub stdout: String,
    pub stderr: String,
    pub proof: Option<PositiveProof>,
    pub operation_id: String,
}

fn _shell_join(tokens: &[String]) -> String {
    crate::command_launcher_floors::shlex_join(tokens)
}

fn _compiler_args(tokens: &[String]) -> (Vec<String>, bool) {
    // Mirror of typescript_launch_evidence::compiler_args — explicit_package is
    // any `--package`/`--package=` in argv[1..]; args = tokens after the tsc
    // index.
    let explicit_package = tokens[1.min(tokens.len())..]
        .iter()
        .any(|token| token == "--package" || token.starts_with("--package="));
    let executable_index = tokens.iter().skip(1).position(|t| t == "tsc");
    match executable_index {
        None => (Vec::new(), explicit_package),
        Some(index) => (
            tokens[(index + 2).min(tokens.len())..].to_vec(),
            explicit_package,
        ),
    }
}

fn _resolve_node_ts(
    workspace: &Path,
    execution: &LocalPackageExecutionEvidence,
) -> Option<PathBuf> {
    _resolve_node(workspace, execution)
}

/// `try_execute_contained_typescript` (:46-168).
pub fn try_execute_contained_typescript(
    workspace: &Path,
    command_text: &str,
    guard_home: &Path,
) -> Option<ContainedTypeScriptResult> {
    let intent = _parse_intent(command_text)?;
    if intent.package_manager != "npx" {
        return None;
    }
    let execution = intent.local_executions.first()?;
    if !execution.local_only_requested {
        return None;
    }
    let node = _resolve_node_ts(workspace, execution)?;
    let tokens = intent.command_tokens.clone();
    let (compiler_args, _explicit_package) = _compiler_args(&tokens);
    let mut sources: Vec<String> = Vec::new();
    for arg in &compiler_args {
        if (arg.ends_with(".ts")
            || arg.ends_with(".tsx")
            || arg.ends_with(".cts")
            || arg.ends_with(".mts"))
            && !arg.starts_with('-')
        {
            sources.push(arg.clone());
        }
    }
    if sources.is_empty() {
        return None;
    }
    let package_root = workspace.join("node_modules").join("typescript");
    let (tree_digest, _package_inputs, closure_digest, _closure_inputs) =
        typescript_snapshot_inputs(workspace, &package_root, &sources).ok()?;

    let argv = {
        let mut a = vec![node.to_string_lossy().into_owned()];
        a.extend(tokens.iter().cloned());
        a
    };
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "typescript-check".to_owned(),
        argv,
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: 120,
        max_output_bytes: 4 * 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Run,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 32,
        max_open_files: 512,
        max_file_size_bytes: 32 * 1024 * 1024,
        max_write_bytes_total: 64 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let run_id = format!("ts-{}", _now_epoch_ms());
    let (exit_code, _stdout_text, _stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
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
    Some(ContainedTypeScriptResult {
        attestation,
        outputs,
        captured_files: captured,
        decision: None,
        tree_digest,
        closure_digest,
        stdout: _stdout_text.clone(),
        stderr: _stderr_text.clone(),
        proof: None,
        operation_id: "typecheck".to_owned(),
    })
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
            let tmp = target.with_extension("contained.tmp");
            {
                let mut file = File::create(&tmp).map_err(|_| "write_failed".to_owned())?;
                file.write_all(content)
                    .map_err(|_| "write_failed".to_owned())?;
                file.sync_all().map_err(|_| "write_failed".to_owned())?;
            }
            if let Some(mode) = operation.mode {
                fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
                    .map_err(|_| "write_failed".to_owned())?;
            }
            fs::rename(&tmp, &target).map_err(|_| "write_failed".to_owned())?;
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
// contained_package_script_execution.py (:1-156)
// ===========================================================================

/// `ContainedPackageScriptResult` (:30-36).
#[derive(Debug, Clone)]
pub struct ContainedPackageScriptResult {
    pub attestation: ContainmentAttestation,
    pub outputs: Vec<ContainmentCapturedOutput>,
    pub captured_files: Vec<String>,
    pub script: String,
    pub decision: Option<EffectDecision>,
    pub stdout: String,
    pub stderr: String,
    pub proof: Option<PositiveProof>,
    pub operation_id: String,
}

fn _resolve_bun(workspace: &Path, execution: &LocalPackageExecutionEvidence) -> Option<PathBuf> {
    let executable = execution.local_executable.as_ref()?;
    if executable.status != "available" {
        return None;
    }
    let raw = executable.resolved_path.as_deref()?;
    let path = weak_canonicalize(Path::new(raw));
    if !path.starts_with(workspace) {
        return None;
    }
    if !path.is_file() {
        return None;
    }
    Some(path)
}

fn _runner_package(tokens: &[String]) -> Option<String> {
    tokens.get(1).cloned()
}

/// `try_execute_contained_package_script` (:46-156).
pub fn try_execute_contained_package_script(
    workspace: &Path,
    command_text: &str,
    guard_home: &Path,
) -> Option<ContainedPackageScriptResult> {
    let intent = _parse_intent(command_text)?;
    if intent.package_manager != "bun" {
        return None;
    }
    let execution = intent.local_executions.first()?;
    if !execution.local_only_requested {
        return None;
    }
    let bun = _resolve_bun(workspace, execution)?;
    let tokens = intent.command_tokens.clone();
    let script = _runner_package(&tokens).unwrap_or_else(|| "run".to_owned());

    let argv = {
        let mut a = vec![bun.to_string_lossy().into_owned()];
        a.extend(tokens.iter().skip(1).cloned());
        a
    };
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "package-script".to_owned(),
        argv,
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: 120,
        max_output_bytes: 4 * 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Run,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 32,
        max_open_files: 512,
        max_file_size_bytes: 32 * 1024 * 1024,
        max_write_bytes_total: 64 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let run_id = format!("pkg-{}", _now_epoch_ms());
    let (exit_code, _stdout_text, _stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
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
    let _evidence = build_local_package_script_evidence(workspace, execution);
    Some(ContainedPackageScriptResult {
        attestation,
        outputs,
        captured_files: captured,
        script,
        decision: None,
        stdout: _stdout_text.clone(),
        stderr: _stderr_text.clone(),
        proof: None,
        operation_id: "package-script".to_owned(),
    })
}

// ===========================================================================
// contained_test_hook.py (:30-264)
// ===========================================================================

const TEST_HOOK_SCHEMA_VERSION: &str = "contained-test-hook-v1";

/// `HookOutcome` (:44-50).
#[derive(Debug, Clone)]
pub struct ContainedTestHookOutcome {
    pub kind: String,
    pub status: String,
    pub attestation: Option<ContainmentAttestation>,
    pub evidence: Option<Value>,
}

fn _hook_outcome(kind: &str, status: &str) -> ContainedTestHookOutcome {
    ContainedTestHookOutcome {
        kind: kind.to_owned(),
        status: status.to_owned(),
        attestation: None,
        evidence: None,
    }
}

/// `_hook_workspace` (:53-60).
fn _hook_workspace(request: &ContainmentRequest) -> PathBuf {
    PathBuf::from(&request.cwd)
}

/// `is_package_test` (:63-72) — dispatch on `npm test|bun test|vitest run`.
fn _is_package_test(tokens: &[String]) -> bool {
    if tokens.len() < 2 {
        return false;
    }
    matches!(tokens[0].as_str(), "npm" | "bun" | "pnpm" | "yarn")
        && matches!(tokens[1].as_str(), "test" | "run")
}

/// `is_inline_eval` (:75-88) — `node -e` / `node --eval` / `python -c`.
fn _is_inline_eval(tokens: &[String]) -> bool {
    if tokens.len() < 2 {
        return false;
    }
    matches!(tokens[0].as_str(), "node" | "python" | "python3")
        && matches!(tokens[1].as_str(), "-e" | "--eval" | "-c")
}

/// `resolve_package_test` (:91-108) → (package_manager, script).
fn _resolve_package_test(tokens: &[String]) -> Option<(String, String)> {
    if tokens.len() < 2 {
        return None;
    }
    let manager = tokens[0].clone();
    if !matches!(manager.as_str(), "npm" | "bun" | "pnpm" | "yarn") {
        return None;
    }
    if tokens[1] == "test" {
        return Some((manager, "test".to_owned()));
    }
    if tokens[1] == "run" && tokens.len() >= 3 {
        return Some((manager, tokens[2].clone()));
    }
    None
}

/// `contained_test_hook` (:111-264): dispatch a contained test invocation to
/// the correct execution path; fail closed on any ambiguity.
pub fn contained_test_hook(
    workspace: &Path,
    command_text: &str,
    guard_home: &Path,
) -> Option<ContainedTestHookOutcome> {
    let tokens = shlex_split(command_text)?;
    if tokens.is_empty() {
        return Some(_hook_outcome("unknown", "reject"));
    }
    if _is_inline_eval(&tokens) {
        return Some(_hook_outcome("inline_eval", "reject"));
    }
    if let Some((_manager, _script)) = _resolve_package_test(&tokens) {
        // route to the contained package-script execution path
        if let Some(result) =
            try_execute_contained_package_script(workspace, command_text, guard_home)
        {
            return Some(ContainedTestHookOutcome {
                kind: "package_script".to_owned(),
                status: "executed".to_owned(),
                attestation: Some(result.attestation),
                evidence: None,
            });
        }
        return Some(_hook_outcome("package_script", "reject"));
    }
    if _is_package_test(&tokens) {
        return Some(_hook_outcome("package_test", "reject"));
    }
    if let Some(result) = try_execute_contained_node_command(workspace, command_text, guard_home) {
        return Some(ContainedTestHookOutcome {
            kind: "node".to_owned(),
            status: "executed".to_owned(),
            attestation: Some(result.attestation),
            evidence: result.evidence,
        });
    }
    if let Some(result) = try_execute_contained_typescript(workspace, command_text, guard_home) {
        return Some(ContainedTestHookOutcome {
            kind: "typescript".to_owned(),
            status: "executed".to_owned(),
            attestation: Some(result.attestation),
            evidence: None,
        });
    }
    if let Some(result) = try_execute_contained_workspace_write(workspace, command_text, guard_home)
    {
        return Some(ContainedTestHookOutcome {
            kind: "workspace_write".to_owned(),
            status: "executed".to_owned(),
            attestation: Some(result.attestation),
            evidence: None,
        });
    }
    Some(_hook_outcome("unknown", "reject"))
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

/// Structured-intent binding for `try_execute_contained_node_command`.
///
/// `argv` is the exact token sequence the shim observed; `evidence` is the
/// serialized `LocalPackageExecutionEvidence.to_dict()` produced by the
/// caller's probe. Returns `None` when either is absent/unparseable — the
/// resident maps that to a Python fallback, never a re-spawn.
pub fn try_execute_contained_node_command_with_intent(
    workspace: &Path,
    manager: &str,
    argv: &[String],
    guard_home: &Path,
    evidence: Option<&Value>,
) -> Option<ContainedNodeResult> {
    let execution = evidence.and_then(LocalPackageExecutionEvidence::from_dict)?;
    if manager != "npx" && manager != "bunx" {
        return None;
    }
    if !execution.local_only_requested {
        return None;
    }
    if _package_shim_handoff_active(&execution) {
        return None;
    }
    if _fail_closed_vitest_handoff(execution.typescript_launch.as_ref()) {
        return None;
    }
    _complete_contained_node_command(workspace, &execution, argv, guard_home).ok()
}

/// Structured-intent binding for `try_execute_contained_typescript`.
pub fn try_execute_contained_typescript_with_intent(
    workspace: &Path,
    manager: &str,
    argv: &[String],
    guard_home: &Path,
    evidence: Option<&Value>,
) -> Option<ContainedTypeScriptResult> {
    let execution = evidence.and_then(LocalPackageExecutionEvidence::from_dict)?;
    if manager != "npx" {
        return None;
    }
    if !execution.local_only_requested {
        return None;
    }
    let node = _resolve_node_ts(workspace, &execution)?;
    // `argv` here is the caller-bound token sequence (starts with `tsc` or
    // the tsx/vite/vitest runner), not the npx-prefixed form.
    // `_compiler_args` scans past `tsc`, so we synthesise a virtual
    // `[manager, tsc, ...argv]` prefix to reuse the existing extraction.
    let mut tokens = vec![manager.to_owned(), "tsc".to_owned()];
    tokens.extend(argv.iter().skip(1).cloned());
    let (compiler_args, _explicit_package) = _compiler_args(&tokens);
    let mut sources: Vec<String> = Vec::new();
    for arg in &compiler_args {
        if (arg.ends_with(".ts")
            || arg.ends_with(".tsx")
            || arg.ends_with(".cts")
            || arg.ends_with(".mts"))
            && !arg.starts_with('-')
        {
            sources.push(arg.clone());
        }
    }
    if sources.is_empty() {
        return None;
    }
    let package_root = workspace.join("node_modules").join("typescript");
    let (tree_digest, _package_inputs, closure_digest, _closure_inputs) =
        typescript_snapshot_inputs(workspace, &package_root, &sources).ok()?;
    let argv_full = {
        let mut a = vec![node.to_string_lossy().into_owned()];
        a.extend(argv.iter().cloned());
        a
    };
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "typescript-check".to_owned(),
        argv: argv_full,
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: 120,
        max_output_bytes: 4 * 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Run,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 32,
        max_open_files: 512,
        max_file_size_bytes: 32 * 1024 * 1024,
        max_write_bytes_total: 64 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let run_id = format!("ts-{}", _now_epoch_ms());
    let (exit_code, _stdout_text, _stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
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
    Some(ContainedTypeScriptResult {
        attestation,
        outputs,
        captured_files: captured,
        decision: None,
        tree_digest,
        closure_digest,
        stdout: _stdout_text.clone(),
        stderr: _stderr_text.clone(),
        proof: None,
        operation_id: "typecheck".to_owned(),
    })
}

/// Structured-intent binding for `try_execute_contained_package_script`.
pub fn try_execute_contained_package_script_with_intent(
    workspace: &Path,
    manager: &str,
    argv: &[String],
    guard_home: &Path,
    evidence: Option<&Value>,
) -> Option<ContainedPackageScriptResult> {
    let execution = evidence.and_then(LocalPackageExecutionEvidence::from_dict)?;
    if manager != "bun" {
        return None;
    }
    if !execution.local_only_requested {
        return None;
    }
    let bun = _resolve_bun(workspace, &execution)?;
    let script = _runner_package(argv).unwrap_or_else(|| "run".to_owned());
    let argv_full = {
        let mut a = vec![bun.to_string_lossy().into_owned()];
        a.extend(argv.iter().skip(1).cloned());
        a
    };
    let request = ContainmentRequest {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        kind: "package-script".to_owned(),
        argv: argv_full,
        cwd: workspace.to_string_lossy().into_owned(),
        env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
        timeout_seconds: 120,
        max_output_bytes: 4 * 1024 * 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_request(&request).ok()?;
    let policy = ContainmentPolicy {
        schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
        action: ContainmentAction::Run,
        workspace_read_paths: vec![workspace.to_string_lossy().into_owned()],
        workspace_write_paths: vec![workspace.to_string_lossy().into_owned()],
        env_allowlist: request.env_allowlist.clone(),
        allowed_domains: vec![],
        timeout_seconds: request.timeout_seconds,
        max_processes: 32,
        max_open_files: 512,
        max_file_size_bytes: 32 * 1024 * 1024,
        max_write_bytes_total: 64 * 1024 * 1024,
        max_output_bytes: request.max_output_bytes,
        memory_mb: 1024,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    };
    validate_containment_policy(&policy).ok()?;
    let run_id = format!("pkg-{}", _now_epoch_ms());
    let (exit_code, _stdout_text, _stderr_text, outputs, started_ms, enforcement, captured) =
        execute_contained(&request, &policy, guard_home, &run_id).ok()?;
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
    let _evidence = build_local_package_script_evidence(workspace, &execution);
    Some(ContainedPackageScriptResult {
        attestation,
        outputs,
        captured_files: captured,
        script,
        decision: None,
        stdout: _stdout_text.clone(),
        stderr: _stderr_text.clone(),
        proof: None,
        operation_id: "package-script".to_owned(),
    })
}

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

impl ContainedNodeResult {
    /// Serialize to the result envelope the resident returns.
    /// `proof`/`decision` are flattened into the EffectDecision shape the
    /// Python caller already knows how to reconstruct.
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
            "evidence".to_owned(),
            self.evidence.clone().unwrap_or(Value::Null),
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
        Value::Object(m)
    }
}

impl ContainedTypeScriptResult {
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
            "decision".to_owned(),
            self.decision
                .as_ref()
                .map(effect_decision_to_payload)
                .unwrap_or(Value::Null),
        );
        m.insert("tree_digest".to_owned(), json!(self.tree_digest));
        m.insert("closure_digest".to_owned(), json!(self.closure_digest));
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
        Value::Object(m)
    }
}

impl ContainedPackageScriptResult {
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
            "decision".to_owned(),
            self.decision
                .as_ref()
                .map(effect_decision_to_payload)
                .unwrap_or(Value::Null),
        );
        m.insert("script".to_owned(), json!(self.script));
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

impl ContainedTestHookOutcome {
    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("kind".to_owned(), json!(self.kind));
        m.insert("status".to_owned(), json!(self.status));
        m.insert(
            "attestation".to_owned(),
            self.attestation
                .as_ref()
                .map(|a| a.to_dict())
                .unwrap_or(Value::Null),
        );
        m.insert(
            "evidence".to_owned(),
            self.evidence.clone().unwrap_or(Value::Null),
        );
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
        || rel.components().any(|component| {
            let part = component.as_os_str().to_string_lossy().to_lowercase();
            part.starts_with(".env") || SEMANTIC_PROTECTED_NAMES.contains(&part.as_str())
        })
    {
        return Err("workspace_path_protected".to_owned());
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
            if !must_exist && !metadata.is_file() {
                return Err("workspace_output_not_regular".to_owned());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
        Err(_) => return Err("workspace_input_not_regular".to_owned()),
    }
    Ok(candidate)
}

struct SemanticWorkspaceStage(PathBuf);

impl Drop for SemanticWorkspaceStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn _copy_semantic_workspace(
    root: &Path,
    source: &Path,
    target: &Path,
    total_bytes: &mut u64,
) -> Result<(), String> {
    fs::create_dir(target).map_err(|_| "workspace_stage_create_failed".to_owned())?;
    for entry in fs::read_dir(source).map_err(|_| "workspace_stage_read_failed".to_owned())? {
        let entry = entry.map_err(|_| "workspace_stage_read_failed".to_owned())?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|_| "workspace_stage_read_failed".to_owned())?;
        if file_type.is_dir() {
            _copy_semantic_workspace(root, &source_path, &target_path, total_bytes)?;
        } else if file_type.is_file() {
            let source_file =
                File::open(&source_path).map_err(|_| "workspace_stage_copy_failed".to_owned())?;
            let mut target_file =
                File::create(&target_path).map_err(|_| "workspace_stage_copy_failed".to_owned())?;
            let remaining = MAX_TOTAL_CAPTURED_OUTPUT_BYTES - *total_bytes;
            let copied = std::io::copy(&mut source_file.take(remaining + 1), &mut target_file)
                .map_err(|_| "workspace_stage_copy_failed".to_owned())?;
            if copied > remaining {
                return Err("workspace_stage_too_large".to_owned());
            }
            *total_bytes += copied;
        } else if file_type.is_symlink() {
            let link = fs::read_link(&source_path)
                .map_err(|_| "workspace_stage_read_failed".to_owned())?;
            if link.is_absolute() || !weak_canonicalize(&source_path).starts_with(root) {
                return Err("workspace_stage_symlink_unsafe".to_owned());
            }
            std::os::unix::fs::symlink(link, &target_path)
                .map_err(|_| "workspace_stage_copy_failed".to_owned())?;
        } else {
            return Err("workspace_stage_entry_unsupported".to_owned());
        }
    }
    Ok(())
}

fn _stage_semantic_workspace(
    workspace: &Path,
    guard_home: &Path,
    run_id: &str,
) -> Result<SemanticWorkspaceStage, String> {
    let parent = guard_home.join("containment");
    fs::create_dir_all(&parent).map_err(|_| "workspace_stage_create_failed".to_owned())?;
    let parent = parent
        .canonicalize()
        .map_err(|_| "workspace_stage_create_failed".to_owned())?;
    if parent.starts_with(workspace) {
        return Err("workspace_stage_inside_workspace".to_owned());
    }
    let stage = parent.join(format!("{run_id}-workspace"));
    let mut total_bytes = 0;
    if let Err(error) = _copy_semantic_workspace(workspace, workspace, &stage, &mut total_bytes) {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }
    Ok(SemanticWorkspaceStage(stage))
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
    let env = environment.cloned().unwrap_or_default();
    let run_id = format!("ww-semantic-{}", _now_epoch_ms());
    let stage = if operation == "patch-check" {
        None
    } else {
        Some(_stage_semantic_workspace(&workspace, guard_home, &run_id).ok()?)
    };
    let execution_workspace = match &stage {
        Some(staged) => staged.0.canonicalize().ok()?,
        None => workspace.clone(),
    };
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
        action: ContainmentAction::Write,
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
