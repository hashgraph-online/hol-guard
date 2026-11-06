//! Port of `native_archive_inspection.py` — mechanical transport adapter for
//! native archive inspection.
//!
//! The original module validates request shape, forwards a bounded JSON
//! request to `hol-guard-runtime archive-inspect --stdin` through
//! `run_isolated_hook_process`, and projects the typed result back to the
//! package evaluator. The runtime probe + worker spawn are behind
//! [`NativeRuntimeProbeApi`] / [`IsolatedHookProcessApi`] seams; the request
//! construction, canonical JSON, deadline math, and response validation are
//! ported line-for-line.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use guard_contracts::{
    NativeRuntimeStatusV1, ARCHIVE_CAP_ARCHIVE_BYTES, ARCHIVE_CAP_EXPANDED_BYTES,
    ARCHIVE_CAP_FILES, ARCHIVE_CAP_MEMBER_BYTES, ARCHIVE_INSPECTION_FEATURE,
    ARCHIVE_INSPECTION_REQUEST_SCHEMA, ARCHIVE_INSPECTION_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// `ArchiveInspectionResult` (native_archive_inspection.py:69) mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInspectionResult {
    /// `clean`, `blocked`, or `incomplete`.
    pub status: String,
    pub code: String,
    pub message: String,
    /// `low`, `medium`, `high`, or `critical`.
    pub severity: String,
    pub sha256: Option<String>,
}

/// Caller-facing defaults (native_archive_inspection.py).
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 30.0;
/// `_DEFAULT_MAX_ARCHIVE_BYTES`.
pub const DEFAULT_MAX_ARCHIVE_BYTES: u64 = ARCHIVE_CAP_ARCHIVE_BYTES;
/// `_DEFAULT_MAX_FILES`.
pub const DEFAULT_MAX_FILES: u64 = ARCHIVE_CAP_FILES;
/// `_DEFAULT_MAX_EXPANDED_BYTES`.
pub const DEFAULT_MAX_EXPANDED_BYTES: u64 = ARCHIVE_CAP_EXPANDED_BYTES;
/// `_DEFAULT_MAX_MEMBER_BYTES`.
pub const DEFAULT_MAX_MEMBER_BYTES: u64 = ARCHIVE_CAP_MEMBER_BYTES;
/// `_DEFAULT_MAX_PACKAGE_JSON_BYTES` (native_archive_inspection.py:60).
pub const DEFAULT_MAX_PACKAGE_JSON_BYTES: u64 = 256 * 1024;
/// `_DEFAULT_MAX_MEMORY_BYTES` (native_archive_inspection.py:61).
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
/// `_DEFAULT_MAX_DECOMPRESSION_RATIO` (native_archive_inspection.py:62).
pub const DEFAULT_MAX_DECOMPRESSION_RATIO: f64 = 200.0;
/// `_DEFAULT_MAX_NESTED_ARCHIVES` (native_archive_inspection.py:63).
pub const DEFAULT_MAX_NESTED_ARCHIVES: u64 = 8;
/// `_DEFAULT_MAX_PATH_DEPTH` (native_archive_inspection.py:64).
pub const DEFAULT_MAX_PATH_DEPTH: u64 = 64;

const REQUEST_SCHEMA: &str = ARCHIVE_INSPECTION_REQUEST_SCHEMA;
const RESULT_SCHEMA: &str = ARCHIVE_INSPECTION_RESULT_SCHEMA;
const NATIVE_FEATURE: &str = ARCHIVE_INSPECTION_FEATURE;
/// `_RESULT_MAX_BYTES` (native_archive_inspection.py:28).
const RESULT_MAX_BYTES: usize = 16 * 1024;
/// `_MAX_CODE_CHARS` (native_archive_inspection.py:29).
const MAX_CODE_CHARS: usize = 128;
/// `_MAX_MESSAGE_CHARS` (native_archive_inspection.py:30).
const MAX_MESSAGE_CHARS: usize = 512;
/// `_MAX_COUNTER` (native_archive_inspection.py:31).
const MAX_COUNTER: u64 = 1 << 62;

/// `_RESULT_KEYS` — every result key the worker may emit.
const RESULT_KEYS: [&str; 10] = [
    "schema",
    "request_id",
    "request_sha256",
    "status",
    "code",
    "message",
    "severity",
    "sha256",
    "runtime_sha256",
    "counters",
];
/// `_COUNTER_KEYS` — allowed counter names.
const COUNTER_KEYS: [&str; 3] = ["members", "expanded_bytes", "elapsed_ms"];

/// `_result` (native_archive_inspection.py:75) — always `incomplete`/`high`
/// on the validation-rejection path.
fn result(
    status: &str,
    code: &str,
    message: &str,
    severity: &str,
    sha256: Option<String>,
) -> ArchiveInspectionResult {
    ArchiveInspectionResult {
        status: status.to_string(),
        code: code.to_string(),
        message: message.to_string(),
        severity: severity.to_string(),
        sha256,
    }
}

/// `_worker_environment` (native_archive_inspection.py:90).
fn worker_environment() -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    environment.insert("LC_ALL".to_string(), "C".to_string());
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                environment.insert(key.to_string(), value);
            }
        }
    }
    environment
}

/// `run_isolated_hook_process` seam (native_archive_inspection.py:20). The
/// process runner owns the deadline, output limit, and containment flags;
/// this seam only projects the completed process back.
pub struct IsolatedHookProcessResult {
    /// `completed.returncode` — `None` when the process could not be spawned.
    pub returncode: Option<i32>,
    pub stdout: String,
    /// `completed.timed_out`.
    pub timed_out: bool,
    /// `completed.output_limit_exceeded`.
    pub output_limit_exceeded: bool,
    /// `completed.containment_failed`.
    pub containment_failed: bool,
}

/// `.codex_hook_launch_runtime.run_isolated_hook_process` seam.
pub trait IsolatedHookProcessApi {
    /// `run_isolated_hook_process(command, input_text=, cwd=, environment=,
    /// deadline_monotonic=, output_limit=, parent_liveness=True)`.
    fn run_isolated_hook_process(
        &self,
        command: &[String],
        input_text: &str,
        cwd: &Path,
        environment: &BTreeMap<String, String>,
        deadline_monotonic: Instant,
        output_limit: usize,
    ) -> IsolatedHookProcessResult;
}

/// `.native_runtime.native_runtime_status` seam (:21 import).
pub trait NativeRuntimeStatusApi {
    /// `native_runtime_status(deadline_monotonic=)` -> `NativeRuntimeStatus`
    /// mirror.
    fn native_runtime_status(&self, deadline_monotonic: Instant) -> NativeRuntimeStatusV1;
}

fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `inspect_archive_native` (native_archive_inspection.py:101).
#[allow(clippy::too_many_arguments)]
pub fn inspect_archive_native(
    path: &Path,
    expected_sha256: &str,
    state_dir: &Path,
    timeout_seconds: f64,
    max_archive_bytes: u64,
    max_files: u64,
    max_expanded_bytes: u64,
    max_member_bytes: u64,
    max_package_json_bytes: u64,
    max_memory_bytes: u64,
    max_decompression_ratio: f64,
    max_nested_archives: u64,
    max_path_depth: u64,
    runtime_status_api: &dyn NativeRuntimeStatusApi,
    process_api: &dyn IsolatedHookProcessApi,
) -> ArchiveInspectionResult {
    // The caller's timeout covers the whole adapter — including the cold-start
    // capabilities probe — so capture the deadline up front.
    let deadline_monotonic =
        Instant::now() + std::time::Duration::from_secs_f64(timeout_seconds.max(0.0) + 0.5);
    let policy_invalid = |_: &str| {
        result(
            "incomplete",
            "external_archive_inspection_policy_invalid",
            "External archive inspection policy is invalid.",
            "high",
            None,
        )
    };
    let expected_sha256_lower = expected_sha256.to_ascii_lowercase();
    if timeout_seconds <= 0.0
        || !timeout_seconds.is_finite()
        || max_archive_bytes == 0
        || max_files == 0
        || max_expanded_bytes == 0
        || max_member_bytes == 0
        || max_package_json_bytes == 0
        || max_memory_bytes == 0
        || !max_decompression_ratio.is_finite()
        || max_decompression_ratio <= 0.0
        || max_nested_archives == u64::MAX // treat as non-finite sentinel
        || max_path_depth == 0
        || !is_lower_hex64(expected_sha256)
    {
        return policy_invalid("");
    }
    // Resolve ancestors only; the leaf keeps its on-disk identity so the
    // native worker's own `lstat` still sees a symlink leaf and rejects it.
    let resolved_parent = match path.parent().and_then(|p| p.canonicalize().ok()) {
        Some(parent) => parent,
        None => {
            return result(
                "incomplete",
                "external_archive_inspection_incomplete",
                "External archive is unavailable for offline inspection.",
                "high",
                None,
            );
        }
    };
    let archive_path = resolved_parent.join(path.file_name().unwrap_or_default());
    let status = runtime_status_api.native_runtime_status(deadline_monotonic);
    let identity = match status.identity.as_ref() {
        Some(identity) => identity.clone(),
        None => {
            return result(
                "incomplete",
                "external_archive_native_unavailable",
                "External archive inspection requires the Guard native runtime.",
                "high",
                None,
            );
        }
    };
    let capabilities = match status.capabilities.as_ref() {
        Some(capabilities) => capabilities.clone(),
        None => {
            return result(
                "incomplete",
                "external_archive_native_unavailable",
                "External archive inspection requires the Guard native runtime.",
                "high",
                None,
            );
        }
    };
    if !status.available
        || !status.compatible
        || !capabilities.features.iter().any(|f| f == NATIVE_FEATURE)
    {
        return result(
            "incomplete",
            "external_archive_native_unavailable",
            "External archive inspection requires the Guard native runtime.",
            "high",
            None,
        );
    }
    let command = [
        identity.path.clone(),
        "archive-inspect".to_string(),
        "--stdin".to_string(),
    ];
    let remaining = deadline_monotonic
        .checked_duration_since(Instant::now())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let worker_budget = remaining - 0.5;
    if worker_budget <= 0.0 {
        return result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            "high",
            None,
        );
    }
    if std::fs::create_dir_all(state_dir).is_err() {
        return result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive inspection lease could not be established.",
            "high",
            None,
        );
    }
    let canonical_state_dir = match state_dir.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            return result(
                "incomplete",
                "external_archive_inspection_incomplete",
                "External archive inspection lease could not be established.",
                "high",
                None,
            );
        }
    };
    let request_id = {
        let mut bytes = [0u8; 16];
        if getrandom::fill(&mut bytes).is_err() {
            return result(
                "incomplete",
                "external_archive_inspection_incomplete",
                "External archive inspection request could not be generated.",
                "high",
                None,
            );
        }
        hex::encode(bytes)
    };
    let timeout_ms = (worker_budget * 1000.0).ceil() as u64;
    let mut caps = Map::new();
    caps.insert("max_archive_bytes".into(), json!(max_archive_bytes));
    caps.insert("max_files".into(), json!(max_files));
    caps.insert("max_expanded_bytes".into(), json!(max_expanded_bytes));
    caps.insert("max_member_bytes".into(), json!(max_member_bytes));
    caps.insert(
        "max_package_json_bytes".into(),
        json!(max_package_json_bytes),
    );
    caps.insert("max_memory_bytes".into(), json!(max_memory_bytes));
    caps.insert(
        "max_decompression_ratio".into(),
        json!(max_decompression_ratio),
    );
    caps.insert("max_nested_archives".into(), json!(max_nested_archives));
    caps.insert("max_path_depth".into(), json!(max_path_depth));
    let mut request = Map::new();
    request.insert("schema".into(), json!(REQUEST_SCHEMA));
    request.insert("request_id".into(), json!(request_id));
    request.insert("archive_path".into(), json!(archive_path.to_string_lossy()));
    request.insert(
        "state_dir".into(),
        json!(canonical_state_dir.to_string_lossy()),
    );
    request.insert("expected_sha256".into(), json!(expected_sha256_lower));
    request.insert("timeout_ms".into(), json!(timeout_ms));
    request.insert("caps".into(), Value::Object(caps));
    // `json.dumps(request, separators=(",", ":"), sort_keys=True)` — the
    // `Map` is `BTreeMap`-ordered, `to_string` emits compact JSON.
    let request_bytes = Value::Object(request.clone()).to_string();
    let request_digest = hex::encode(Sha256::digest(request_bytes.as_bytes()));
    let completed = process_api.run_isolated_hook_process(
        &command,
        &request_bytes,
        archive_path.parent().unwrap_or_else(|| Path::new(".")),
        &worker_environment(),
        deadline_monotonic,
        RESULT_MAX_BYTES + 1024,
    );
    if completed.timed_out {
        return result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            "high",
            None,
        );
    }
    if completed.returncode != Some(0)
        || completed.output_limit_exceeded
        || completed.containment_failed
        || completed.stdout.len() > RESULT_MAX_BYTES
    {
        return result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector did not complete successfully.",
            "high",
            None,
        );
    }
    let payload: Value = match serde_json::from_str(completed.stdout.trim()) {
        Ok(value) => value,
        Err(_) => {
            return result(
                "incomplete",
                "external_archive_inspection_incomplete",
                "External archive offline inspector returned an invalid result.",
                "high",
                None,
            );
        }
    };
    let obj = match payload.as_object() {
        Some(obj) => obj,
        None => {
            return result(
                "incomplete",
                "external_archive_inspection_incomplete",
                "External archive offline inspector returned an invalid result.",
                "high",
                None,
            );
        }
    };
    // `_RESULT_KEYS.issuperset(payload)` — reject unexpected keys.
    if obj.keys().any(|key| !RESULT_KEYS.contains(&key.as_str())) {
        return result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            "high",
            None,
        );
    }
    let get_str = |key: &str| obj.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let status_value = get_str("status");
    let code = get_str("code");
    let message = get_str("message");
    let severity = get_str("severity");
    let sha256_value = obj
        .get("sha256")
        .and_then(|v| v.as_str().map(str::to_string));
    let runtime_sha256 = get_str("runtime_sha256");
    let counters = obj.get("counters").and_then(|v| v.as_object());
    let counters_valid = counters
        .map(|c| {
            c.keys().all(|k| COUNTER_KEYS.contains(&k.as_str()))
                && c.values().all(|v| {
                    v.as_u64().map(|n| n <= MAX_COUNTER).unwrap_or(false) && !v.is_boolean()
                })
        })
        .unwrap_or(false);
    let hex64 = is_lower_hex64;
    if obj.get("schema").and_then(|v| v.as_str()) != Some(RESULT_SCHEMA)
        || obj.get("request_id").and_then(|v| v.as_str())
            != request.get("request_id").and_then(|v| v.as_str())
        || obj.get("request_sha256").and_then(|v| v.as_str()) != Some(request_digest.as_str())
        || !matches!(
            status_value.as_deref(),
            Some("clean" | "blocked" | "incomplete")
        )
        || !code
            .as_deref()
            .map(|c| !c.is_empty() && c.len() <= MAX_CODE_CHARS)
            .unwrap_or(false)
        || !message
            .as_deref()
            .map(|m| !m.is_empty() && m.len() <= MAX_MESSAGE_CHARS)
            .unwrap_or(false)
        || !matches!(
            severity.as_deref(),
            Some("low" | "medium" | "high" | "critical")
        )
        || match sha256_value.as_deref() {
            Some(value) => !hex64(value),
            None => false,
        }
        || runtime_sha256.as_deref().map(|v| !hex64(v)).unwrap_or(true)
        || runtime_sha256.as_deref() != Some(identity.sha256.as_str())
        || !counters_valid
    {
        return result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            "high",
            None,
        );
    }
    let status_value = status_value.unwrap_or_default();
    if status_value == "clean" && sha256_value.as_deref() != Some(expected_sha256_lower.as_str()) {
        return result(
            "blocked",
            "external_archive_digest_mismatch",
            "External archive inspector did not verify the expected digest.",
            "high",
            sha256_value,
        );
    }
    ArchiveInspectionResult {
        status: status_value,
        code: code.unwrap_or_default(),
        message: message.unwrap_or_default(),
        severity: severity.unwrap_or_default(),
        sha256: sha256_value,
    }
}
