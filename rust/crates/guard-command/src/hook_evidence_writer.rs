//! `daemon/runtime_hook_evidence_writer.py` — background evidence writer
//! (RTM-024): a bounded queue plus append-durable JSONL journal keeping
//! best-effort command-activity / native-decision-receipt / MCP-discovery
//! writes outside the security-decision workers.
//!
//! TODO(deps): the surrounding evidence seams are still Python-owned. Store
//! writes (`record_command_activity`, `record_composio_discovery`,
//! `record_native_decision_receipt`, `transition_command_activity`,
//! `is_exact_command_activity_pre_replay`), the journal filesystem
//! helpers (`runtime_hook_evidence_journal`), correlation derivation and
//! receipt building (`command_activity_privacy`, `command_activity_lifecycle`,
//! `command_activity_display`, `native_decision_receipt`), observed-MCP /
//! Composio parsing (`observed_mcp_tools`, `composio_discovery`,
//! `composio_workflows`), and `sqlite_connect_timeout_override` all sit behind
//! seam traits passed through [`EvidenceWriterDeps`]. The journal record
//! types, `serialized()` byte shapes, and `from_json` validators are ported
//! here because the writer owns their lifecycle end to end; `Mapping[str,
//! object]` → `&Map<String, Value>` per crate convention.
//!
//! Threading: Python relies on the stdlib `Condition`/daemon-`Thread` pair;
//! the Rust port uses `Mutex<EvidenceState>` + `Condvar` with identical
//! wakeup, batching, drain-deadline, and dedupe semantics.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::hook_evidence_deferred_post::persist_deferred_post_hook_command_activity;
use crate::local_supply_chain::utc_now_iso;
use guard_contracts::{is_guard_action, write_canonical_json_with_limit};

/// `_open(..., os.O_APPEND | os.O_CREAT | os.O_WRONLY)` mode bits (journal).
const JOURNAL_FILE_MODE: u32 = 0o600;
/// Journal records are bounded to `_max_bytes`; serialized payload size is
/// capped at this parity bound before canonicalization can reject it.
const MAX_SERIALIZED_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// A drain deadline bounds the records a stop waits for the worker to persist.
/// Leaving the loop afterwards costs one wakeup, and this is the slack that
/// wakeup gets, so a stop asking for no drain at all still collects a worker
/// that had nothing to do.
const WORKER_EXIT_GRACE: Duration = Duration::from_millis(250);
/// A record whose store write failed waits this long before its next attempt,
/// doubling with each further failure up to [`RETRY_BACKOFF_CAP`]: the
/// `min(1.0, 0.05 * 2 ** (attempt - 1))` the Python writer waited.
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(50);
const RETRY_BACKOFF_CAP: Duration = Duration::from_secs(1);
/// Store writes a record gets when the store refuses it for a reason other
/// than a lock, before it is dropped. A write the store can never take, such
/// as one that breaks a constraint or evidence that cannot be built, then
/// leaves the queue and the journal instead of being replayed forever. A lock
/// is waited out however long it lasts: see [`PersistOutcome::Busy`].
const MAX_STORE_ATTEMPTS: u32 = 8;

/// The wait before the attempt that follows failure number `attempt`.
fn retry_backoff(attempt: u32) -> Duration {
    RETRY_BACKOFF_BASE
        .saturating_mul(1 << attempt.saturating_sub(1).min(5))
        .min(RETRY_BACKOFF_CAP)
}

/// Whether `record` may be written now: it never failed, or its backoff is
/// over.
fn is_due(state: &EvidenceState, record: &EvidenceRecord, now: Instant) -> bool {
    state
        .retry_at
        .get(&record.record_id())
        .is_none_or(|at| *at <= now)
}

// ---------------------------------------------------------------------------
// Dependency seams — traits replacing unported modules (see TODO(deps)).
// ---------------------------------------------------------------------------

/// `GuardStore` evidence sink (`store_*.py` methods + `guard_home`).
pub trait EvidenceStoreApi {
    /// `store.guard_home`.
    fn guard_home(&self) -> PathBuf;
    /// `store.is_exact_command_activity_pre_replay(evidence)` — `Err` =
    /// lookup failure.
    fn is_exact_command_activity_pre_replay(
        &self,
        evidence: &Map<String, Value>,
    ) -> Result<bool, io::Error>;
    /// `store.record_command_activity(evidence, invocation_preview=)` —
    /// `Ok(false)` = exact replay; `Err` = persistence failure.
    fn record_command_activity(
        &self,
        evidence: &Map<String, Value>,
        invocation_preview: Option<&str>,
    ) -> Result<bool, io::Error>;
    /// `store.record_composio_discovery(source, actions, *, seen_at=,
    /// proposals=)` — `Err` = persistence failure.
    fn record_composio_discovery(
        &self,
        source: &ObservedMcpTool,
        actions: &[ComposioActionSchema],
        seen_at: &str,
        proposals: &[ComposioWorkflowProposal],
    ) -> Result<(), io::Error>;
    /// `store.record_native_decision_receipt(receipt)` — `Ok(false)` =
    /// deduped/rejected result; `Err` = persistence failure.
    fn record_native_decision_receipt(
        &self,
        receipt: &Map<String, Value>,
    ) -> Result<bool, io::Error>;
    /// `store.get_command_activity_by_request_correlation(correlation)` —
    /// `Ok(None)` = no pre-hook row under that handle.
    fn command_activity_by_request_correlation(
        &self,
        correlation: &CorrelationHandle,
    ) -> Result<Option<Map<String, Value>>, io::Error>;
    /// `store.transition_command_activity(current)` — `Ok(false)` = the stored
    /// row already carried this proof.
    fn transition_command_activity(&self, current: &Map<String, Value>) -> Result<bool, io::Error>;
    /// `store.record_command_activity_observation_conflict(occurred_at=)`.
    fn record_command_activity_observation_conflict(
        &self,
        occurred_at: &str,
    ) -> Result<(), io::Error>;
}

/// `command_activity_*` seams: correlation derivation, command preview, and
/// policy-only evidence construction.
pub trait CorrelationApi {
    /// `load_or_create_installation_correlation_key(guard_home)` — `Err`
    /// covers `(OSError, ValueError)`; `Ok(None)` = key absent/unusable.
    fn load_or_create_installation_correlation_key(
        &self,
    ) -> Result<Option<InstallationCorrelationKey>, io::Error>;
    /// `derive_proven_request_correlation(harness=, event=, payload=, key=)` —
    /// `Err` covers `(OSError, ValueError)` retry-triggering failures.
    fn derive_proven_request_correlation(
        &self,
        harness: &str,
        event: &str,
        payload: &Map<String, Value>,
        key: &InstallationCorrelationKey,
    ) -> Result<Option<CorrelationHandle>, io::Error>;
    /// `build_invocation_preview_from_payload(payload)` — `Err` surfaces the
    /// Python `except Exception` drop path.
    fn build_invocation_preview_from_payload(
        &self,
        payload: &Map<String, Value>,
    ) -> Result<Option<String>, io::Error>;
    /// `build_policy_only_pre_hook_evidence(*, activity_id, occurred_at,
    /// harness, policy_action, request_correlation, receipt_id, prompted,
    /// approval_reuse_status)`.
    #[allow(clippy::too_many_arguments)]
    fn build_policy_only_pre_hook_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        policy_action: &str,
        request_correlation: Option<&CorrelationHandle>,
        receipt_id: Option<&str>,
        prompted: bool,
        approval_reuse_status: &str,
    ) -> Result<Map<String, Value>, io::Error>;
    /// `build_unpaired_post_evidence(*, activity_id, occurred_at, harness,
    /// succeeded)` — post-hook evidence claiming no pre-hook decision.
    fn build_unpaired_post_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error>;
    /// `build_correlated_post_activity(previous, *, request_correlation,
    /// succeeded)` — `Err` covers the Python `ValueError` guards.
    fn build_correlated_post_activity(
        &self,
        previous: &Map<String, Value>,
        request_correlation: &CorrelationHandle,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error>;
}

/// `native_decision_receipt` / journal validation seam.
pub trait ReceiptValidationApi {
    /// `validate_native_decision_receipt(value)` — returns the copied receipt.
    fn validate_native_decision_receipt(
        &self,
        value: &Map<String, Value>,
    ) -> Option<Map<String, Value>>;
}

/// `observed_mcp_tools` / `composio_*` seams.
pub trait ComposioApi {
    /// `observed_mcp_tool(harness, tool_name)`; `harness` must round-trip.
    fn observed_mcp_tool(&self, harness: &str, tool_name: &str) -> Option<ObservedMcpTool>;
    /// `composio_discovered_actions(tool_name, response)`.
    fn composio_discovered_actions(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> Option<Vec<ComposioActionSchema>>;
    /// `composio_workflow_proposals(tool_name, response)`.
    fn composio_workflow_proposals(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> Option<Vec<ComposioWorkflowProposal>>;
}

/// Journal filesystem seam (`runtime_hook_evidence_journal` helpers +
/// `datetime.now(timezone.utc)` inside `append_journal`).
pub trait EvidenceJournalApi {
    /// `append_journal(path, record)` — lock, `O_APPEND`, fsync, then the
    /// preview sidecar. The sidecar write shares the record's fate, as it does
    /// in Python: a failure there truncates the appended record back off the
    /// journal rather than leaving a record whose preview was never stored.
    /// `Err` = `OSError`.
    fn append_journal(&self, path: &Path, record: &EvidenceRecord) -> Result<(), io::Error>;
    /// `rewrite_journal(path, *, remove_record_id=, max_bytes=)` — returns
    /// the count of dropped invalid records; `Err` = `OSError`.
    fn rewrite_journal(
        &self,
        path: &Path,
        remove_record_id: &str,
        max_bytes: usize,
    ) -> Result<u64, io::Error>;
    /// `recover_journal_records(path, *, max_bytes=)` — raw JSON objects plus
    /// invalid-line count; `Err` = `OSError` (caller handles `NotFound`).
    fn recover_journal_records(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error>;
    /// `utc_now_iso()` inside `append_journal`.
    fn now_utc_iso(&self) -> String;
}

/// `sqlite_connect_timeout_override(NonZeroU32)` context-manager seam. The
/// returned guard keeps the override installed until dropped.
pub trait SqliteTimeoutApi {
    /// Enter `sqlite_connect_timeout_override`; the guard restores on drop.
    fn sqlite_timeout_override(&self, timeout_ms: NonZeroU32) -> Box<dyn std::any::Any + Send>;
}

/// Bundled dependency seams for [`RuntimeHookEvidenceWriter`].
pub struct EvidenceWriterDeps {
    pub correlation: Box<dyn CorrelationApi + Send + Sync>,
    /// Shared with the journal, which decides what a rewrite keeps.
    pub receipts: Arc<dyn ReceiptValidationApi + Send + Sync>,
    pub composio: Arc<dyn ComposioApi + Send + Sync>,
    pub journal: Box<dyn EvidenceJournalApi + Send + Sync>,
    pub sqlite_timeout: Box<dyn SqliteTimeoutApi + Send + Sync>,
}

// ---------------------------------------------------------------------------
// Value types mirrored from unported runtime modules (minimal surfaces the
// writer consumes; their owning ports may promote them later).
// ---------------------------------------------------------------------------

/// `runtime.command_activity_privacy.InstallationCorrelationKey` — opaque
/// per-install HMAC material plus a non-secret rotation id.
pub struct InstallationCorrelationKey {
    pub key_id: String,
    material: Vec<u8>,
}

impl InstallationCorrelationKey {
    /// `InstallationCorrelationKey(*, key_id, material)` — parity validation:
    /// material must carry at least 32 random bytes.
    pub fn new(key_id: &str, material: &[u8]) -> Result<Self, io::Error> {
        if material.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "correlation key material must contain at least 32 random bytes",
            ));
        }
        Ok(Self {
            key_id: key_id.to_string(),
            material: material.to_vec(),
        })
    }

    /// HMAC material, never logged or serialized.
    pub fn material(&self) -> &[u8] {
        &self.material
    }
}

/// `runtime.command_activity_contract.CorrelationHandle` — privacy-preserving
/// join key: kind, canonical harness, rotation id, keyed digest.
#[derive(Debug, Clone)]
pub struct CorrelationHandle {
    /// `CorrelationKind.value` (e.g. `"command_execution"`, `"workflow_approval"`).
    pub kind: String,
    pub harness: String,
    pub key_id: String,
    pub digest: String,
}

/// `runtime.observed_mcp_tools.ObservedMcpTool` — the connector-boundary
/// identity of one observed `mcp__…` tool.
#[derive(Debug, Clone)]
pub struct ObservedMcpTool {
    /// Canonical harness id (`claude-code`, `cursor`, …).
    pub harness: String,
    /// Fully qualified `mcp__<server>__<tool>` name.
    pub qualified_name: String,
    /// `source.identity` passed to `ensure_local_mcp_observation`.
    pub identity: ObservedCliIdentity,
    /// Server descriptor consumed by `record_composio_discovery`.
    pub server: ObservedMcpServerIdentity,
}

/// `ObservedMcpTool.identity` — the `UnlistedCliIdentity` the connector
/// boundary stands in for, as `ensure_local_mcp_observation` records it. The
/// observed form never carries a source path, runner or path class, so only
/// the fields that call site reads are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCliIdentity {
    pub cli_id: String,
    /// The MCP server segment of the tool name.
    pub name: String,
    /// Always `executable` for an observed connector.
    pub kind: String,
    pub identity_hash: String,
    /// The `mcp__<server>__` namespace.
    pub example_label: String,
    pub interpreter_name: Option<String>,
}

/// Server identity carried inside [`ObservedMcpTool`].
#[derive(Debug, Clone)]
pub struct ObservedMcpServerIdentity {
    pub identity_hash: String,
    pub command: Option<String>,
    pub args_hash: String,
}

/// `runtime.composio_discovery.ComposioActionSchema` — one discovered action.
#[derive(Debug, Clone)]
pub struct ComposioActionSchema {
    pub toolkit: String,
    pub tool_slug: String,
    pub description: String,
    pub input_schema: Map<String, Value>,
    /// Python `full_schema` — serialized as `hasFullSchema`.
    pub full_schema: bool,
}

/// `runtime.composio_workflows.ComposioWorkflowProposal`.
#[derive(Debug, Clone, PartialEq)]
pub struct ComposioWorkflowProposal {
    pub primary: Vec<String>,
    pub supporting: Vec<String>,
    pub guidance_present: bool,
}

// ---------------------------------------------------------------------------
// Journal evidence records (`_CommandActivityRecord`,
// `_NativeDecisionReceiptRecord`, `_McpDiscoveryRecord` + the union).
// ---------------------------------------------------------------------------

/// `_EVIDENCE_SCHEMA` (:36) — command-activity journal envelope.
const EVIDENCE_SCHEMA: &str = "hol-guard-native-hook-evidence.v1";
/// `runtime_hook_mcp_evidence` schema marker.
const MCP_PROVIDER_SCHEMA: &str = "hol-guard-mcp-provider-evidence.v1";
/// `native_decision_receipt.NATIVE_HOOK_DECISION_RECEIPT_SCHEMA`.
const RECEIPT_SCHEMA: &str = "hol-native-decision-receipt.v1";

static SAFE_IDENTIFIER: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$").expect("valid _SAFE_IDENTIFIER regex")
});

/// `_safe_identifier` (:40-42).
fn _safe_identifier(value: &str, fallback: &str) -> String {
    let normalized = value.trim();
    if SAFE_IDENTIFIER.is_match(normalized) {
        normalized.to_string()
    } else {
        fallback.to_string()
    }
}

/// `_payload_has_command` (journal :471-482) — conservative command presence
/// check across harness argument spellings.
pub fn _payload_has_command(payload: &Map<String, Value>) -> bool {
    let arguments = payload
        .get("tool_input")
        .or_else(|| payload.get("toolInput"))
        .or_else(|| payload.get("arguments"));
    if let Some(command_arguments) = arguments.and_then(Value::as_object) {
        for key in ["command", "cmd", "shell_command", "shellCommand"] {
            if command_arguments
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            {
                return true;
            }
        }
    }
    for key in ["command", "cmd"] {
        if payload
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return true;
        }
    }
    false
}

/// `_CommandActivityRecord` (:44-160) — one durable hook-activity record.
#[derive(Debug, Clone)]
pub struct CommandActivityRecord {
    pub record_id: String,
    pub harness: String,
    pub event: String,
    pub correlation: Option<CorrelationHandle>,
    pub has_command: bool,
    pub succeeded: bool,
    /// `json.dumps(payload)` byte length — never the payload itself.
    pub payload_bytes: usize,
    pub attempts: u32,
    pub policy_action: Option<String>,
    pub occurred_at: Option<String>,
    pub receipt_id: Option<String>,
    /// Python field name `prompted` — serialized `interaction_observed`.
    pub prompted: bool,
    pub approval_reuse_status: String,
    /// Private sidecar value, never journaled inline.
    pub invocation_preview: Option<String>,
}

impl CommandActivityRecord {
    /// `_CommandActivityRecord.record_id`.
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// `serialized()` (:62-93) — `sort_keys=True`, compact separators, ASCII.
    pub fn serialized(&self) -> Vec<u8> {
        let correlation = self.correlation.as_ref().map(|correlation| {
            json!({
                "kind": _safe_identifier(&correlation.kind, "unknown"),
                "harness": _safe_identifier(&correlation.harness, "unknown"),
                "key_id": _safe_identifier(&correlation.key_id, "redacted"),
                "digest": _safe_identifier(&correlation.digest, "redacted"),
            })
        });
        let payload = json!({
            "schema": EVIDENCE_SCHEMA,
            "record_id": _safe_identifier(&self.record_id, "redacted"),
            "harness": _safe_identifier(&self.harness, "unknown"),
            "event": _safe_identifier(&self.event, "unknown"),
            "correlation": correlation,
            "has_command": self.has_command,
            "succeeded": self.succeeded,
            "policy_action": self.policy_action,
            "occurred_at": self.occurred_at,
            "receipt_id": self.receipt_id,
            "interaction_observed": self.prompted,
            "approval_reuse_status": self.approval_reuse_status,
        });
        let mut encoded = Vec::new();
        if write_canonical_json_with_limit(
            &payload,
            &mut encoded,
            MAX_SERIALIZED_RECORD_BYTES,
            "record too large",
        )
        .is_err()
        {
            // Unreachable for in-memory shapes; fall back to serde parity.
            encoded = serde_json::to_vec(&payload).unwrap_or_default();
        }
        encoded.push(b'\n');
        encoded
    }
}

/// `_NativeDecisionReceiptRecord` (:186-215) — validated aggregate-only
/// receipt retained by the bounded writer.
#[derive(Debug, Clone)]
pub struct NativeDecisionReceiptRecord {
    pub receipt: Map<String, Value>,
    pub payload_bytes: usize,
    pub attempts: u32,
}

impl NativeDecisionReceiptRecord {
    /// `record_id` property (:190-192) — `str(receipt["decision_id"])`.
    pub fn record_id(&self) -> String {
        match self.receipt.get("decision_id") {
            Some(Value::String(id)) => id.clone(),
            Some(value) => value.to_string(),
            None => String::new(),
        }
    }

    /// `serialized()` (:194-205) — `ensure_ascii=False` compact sorted JSON.
    /// UTF-8 stays unescaped per the Python contract.
    pub fn serialized(&self) -> Vec<u8> {
        let mut encoded =
            serde_json::to_vec(&Value::Object(self.receipt.clone())).unwrap_or_default();
        encoded.push(b'\n');
        encoded
    }

    /// `from_json` (:207-215) — schema gate plus full receipt validation.
    pub fn from_json(
        value: &Map<String, Value>,
        receipts: &dyn ReceiptValidationApi,
    ) -> Option<Self> {
        if value.get("schema") != Some(&json!(RECEIPT_SCHEMA)) {
            return None;
        }
        let receipt = receipts.validate_native_decision_receipt(value)?;
        let record = Self {
            receipt,
            payload_bytes: 0,
            attempts: 0,
        };
        let payload_bytes = record.serialized().len();
        Some(Self {
            receipt: record.receipt,
            payload_bytes,
            attempts: 0,
        })
    }
}

/// `_McpDiscoveryRecord` (`runtime_hook_mcp_evidence` :18-137).
#[derive(Debug, Clone)]
pub struct McpDiscoveryRecord {
    pub record_id: String,
    pub harness: String,
    pub tool_name: String,
    pub occurred_at: String,
    pub actions: Vec<ComposioActionSchema>,
    pub proposals: Vec<ComposioWorkflowProposal>,
    pub payload_bytes: usize,
    pub attempts: u32,
}

impl McpDiscoveryRecord {
    /// `_McpDiscoveryRecord.record_id` — the dataclass field.
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// `serialized()` (:28-62) — sorted compact ASCII JSON + newline.
    pub fn serialized(&self) -> Vec<u8> {
        let tool_schemas: Map<String, Value> = self
            .actions
            .iter()
            .map(|action| {
                (
                    action.tool_slug.clone(),
                    json!({
                        "toolkit": action.toolkit,
                        "tool_slug": action.tool_slug,
                        "description": action.description,
                        "input_schema": action.input_schema,
                        "hasFullSchema": action.full_schema,
                    }),
                )
            })
            .collect();
        let workflow_proposals: Vec<Value> = self
            .proposals
            .iter()
            .map(|item| {
                json!({
                    "primary": item.primary,
                    "supporting": item.supporting,
                    "guidance_present": item.guidance_present,
                })
            })
            .collect();
        let payload = json!({
            "schema": MCP_PROVIDER_SCHEMA,
            "record_id": self.record_id,
            "harness": self.harness,
            "tool_name": self.tool_name,
            "occurred_at": self.occurred_at,
            "tool_schemas": tool_schemas,
            "workflow_proposals": workflow_proposals,
        });
        let mut encoded = Vec::new();
        if write_canonical_json_with_limit(
            &payload,
            &mut encoded,
            MAX_SERIALIZED_RECORD_BYTES,
            "record too large",
        )
        .is_err()
        {
            encoded = serde_json::to_vec(&payload).unwrap_or_default();
        }
        encoded.push(b'\n');
        encoded
    }

    /// `from_json` (:64-136) — schema/field-set gate, identifier validation,
    /// observed-source round-trip, timestamp shape, and replayed Composio
    /// extraction (never retaining raw proposal text).
    pub fn from_json(value: &Map<String, Value>, composio: &dyn ComposioApi) -> Option<Self> {
        if value.get("schema") != Some(&json!(MCP_PROVIDER_SCHEMA)) {
            return None;
        }
        let mut keys: Vec<&str> = value.keys().map(String::as_str).collect();
        keys.sort_unstable();
        const BASE_KEYS: [&str; 6] = [
            "schema",
            "record_id",
            "harness",
            "tool_name",
            "occurred_at",
            "tool_schemas",
        ];
        let has_proposals = keys.contains(&"workflow_proposals");
        if keys.len() != if has_proposals { 7 } else { 6 }
            || !BASE_KEYS.iter().all(|key| keys.contains(key))
        {
            return None;
        }
        let record_id = value.get("record_id")?.as_str()?;
        let harness = value.get("harness")?.as_str()?;
        let tool_name = value.get("tool_name")?.as_str()?;
        let occurred_at = value.get("occurred_at")?.as_str()?;
        if !SAFE_IDENTIFIER.is_match(record_id) || occurred_at.len() > 64 {
            return None;
        }
        let source = composio.observed_mcp_tool(harness, tool_name)?;
        if source.harness != harness {
            return None;
        }
        // Python `datetime.fromisoformat` on 3.10 rejects the `Z` suffix; the
        // ported timestamp check mirrors `utc_now_iso` output shape loosely
        // via the seam-owned parser contract — a trailing `Z` or `+00:00`
        // timezone-aware RFC 3339 value only.
        if !_timestamp_is_utc_aware(occurred_at) {
            return None;
        }
        let actions = composio.composio_discovered_actions(
            tool_name,
            &json!({
                "successful": true,
                "error": null,
                "data": {"tool_schemas": value.get("tool_schemas")},
            }),
        )?;
        // Python reads this with `.get("workflow_proposals", [])`, so the
        // six-key form the key check above accepts has to survive here too:
        // a record written without proposals is still valid evidence.
        let raw_proposals = value
            .get("workflow_proposals")
            .cloned()
            .unwrap_or_else(|| json!([]));
        {
            let raw = raw_proposals.as_array()?;
            if raw.len() > 50
                || !raw.iter().all(|item| {
                    item.as_object().is_some_and(|obj| {
                        obj.len() == 3
                            && obj.contains_key("primary")
                            && obj.contains_key("supporting")
                            && obj.get("guidance_present").is_some_and(Value::is_boolean)
                    })
                })
            {
                return None;
            }
        }
        let proposals = composio.composio_workflow_proposals(
            tool_name,
            &json!({
                "successful": true,
                "error": null,
                "data": {
                    "results": raw_proposals
                        .as_array()
                        .unwrap_or(&Vec::new())
                        .iter()
                        .map(|item| {
                            let guidance = item
                                .get("guidance_present")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            json!({
                                "primary_tool_slugs": item.get("primary"),
                                "related_tool_slugs": item.get("supporting"),
                                "recommended_plan_steps": if guidance { json!(["present"]) } else { json!([]) },
                            })
                        })
                        .collect::<Vec<Value>>(),
                },
            }),
        )?;
        if raw_proposals
            .as_array()
            .is_some_and(|raw| proposals.len() != raw.len())
        {
            return None;
        }
        let record = Self {
            record_id: record_id.to_string(),
            harness: harness.to_string(),
            tool_name: tool_name.to_string(),
            occurred_at: occurred_at.to_string(),
            actions,
            proposals,
            payload_bytes: 0,
            attempts: 0,
        };
        let payload_bytes = record.serialized().len();
        Some(Self {
            payload_bytes,
            ..record
        })
    }
}

/// `_timestamp_is_utc_aware` — the from_json `datetime.fromisoformat` check:
/// a parseable RFC 3339 timestamp carrying an explicit offset or `Z`.
fn _timestamp_is_utc_aware(value: &str) -> bool {
    // Minimal structural gate matching the Python acceptance surface: digits
    // and separators plus a timezone designator (`Z` or `±HH:MM`).
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let tail = value.strip_suffix('Z');
    if tail.is_some() {
        return value[..value.len() - 1]
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | ' ' | '+'));
    }
    // `+HH:MM` / `-HH:MM` offset at the tail.
    if value.len() >= 6 {
        let offset = &value[value.len() - 6..];
        if (offset.starts_with('+') || offset.starts_with('-'))
            && offset.chars().skip(1).take(2).all(|c| c.is_ascii_digit())
            && offset.chars().nth(3) == Some(':')
            && offset.chars().skip(4).all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// `_EvidenceRecord` union (:218).
#[derive(Debug, Clone)]
pub enum EvidenceRecord {
    CommandActivity(CommandActivityRecord),
    NativeDecisionReceipt(NativeDecisionReceiptRecord),
    McpDiscovery(McpDiscoveryRecord),
}

impl EvidenceRecord {
    /// Shared `record_id` accessor across the union.
    pub fn record_id(&self) -> String {
        match self {
            Self::CommandActivity(record) => record.record_id.clone(),
            Self::NativeDecisionReceipt(record) => record.record_id(),
            Self::McpDiscovery(record) => record.record_id.clone(),
        }
    }

    /// Shared `payload_bytes` accessor.
    pub fn payload_bytes(&self) -> usize {
        match self {
            Self::CommandActivity(record) => record.payload_bytes,
            Self::NativeDecisionReceipt(record) => record.payload_bytes,
            Self::McpDiscovery(record) => record.payload_bytes,
        }
    }

    /// Shared `serialized` accessor.
    pub fn serialized(&self) -> Vec<u8> {
        match self {
            Self::CommandActivity(record) => record.serialized(),
            Self::NativeDecisionReceipt(record) => record.serialized(),
            Self::McpDiscovery(record) => record.serialized(),
        }
    }

    /// `isinstance(record, _NativeDecisionReceiptRecord)`.
    fn is_receipt(&self) -> bool {
        matches!(self, Self::NativeDecisionReceipt(_))
    }

    /// Dispatch `from_json` on the record variant matching `schema`.
    fn from_json(
        value: &Map<String, Value>,
        receipts: &dyn ReceiptValidationApi,
        composio: &dyn ComposioApi,
    ) -> Option<Self> {
        match value.get("schema").and_then(Value::as_str) {
            Some(RECEIPT_SCHEMA) => NativeDecisionReceiptRecord::from_json(value, receipts)
                .map(Self::NativeDecisionReceipt),
            Some(MCP_PROVIDER_SCHEMA) => {
                McpDiscoveryRecord::from_json(value, composio).map(Self::McpDiscovery)
            }
            Some(EVIDENCE_SCHEMA) => {
                _command_activity_record_from_json(value).map(Self::CommandActivity)
            }
            _ => None,
        }
    }
}

/// `_CommandActivityRecord.from_json` (:95-160) — strict typed field check;
/// the correlation handle is rebuilt through `CorrelationKind(...)`.
fn _command_activity_record_from_json(value: &Map<String, Value>) -> Option<CommandActivityRecord> {
    let record_id = value.get("record_id")?;
    let harness = value.get("harness")?;
    let event = value.get("event")?;
    let correlation_value = value.get("correlation");
    let has_command = value.get("has_command")?;
    let succeeded = value.get("succeeded")?;
    let policy_action = value.get("policy_action");
    if let Some(action) = policy_action {
        match action {
            Value::Null => {}
            v @ Value::String(_) if is_guard_action(v) => {}
            _ => return None,
        }
    }
    let occurred_at = value.get("occurred_at");
    if let Some(stamp) = occurred_at {
        if !stamp.is_null() {
            let stamp = stamp.as_str()?;
            if !_timestamp_is_utc_aware(stamp) {
                return None;
            }
        }
    }
    let policy_action_str = policy_action.and_then(Value::as_str);
    if policy_action_str.is_some()
        && (event != &json!("PreToolUse")
            || occurred_at.is_none()
            || occurred_at == Some(&Value::Null))
    {
        return None;
    }
    let receipt_id = value.get("receipt_id");
    let prompted = value
        .get("interaction_observed")
        .cloned()
        .unwrap_or(json!(false));
    let reuse = value
        .get("approval_reuse_status")
        .cloned()
        .unwrap_or(json!("not-applicable"));
    if let Some(id) = receipt_id {
        if !id.is_null() {
            let id = id.as_str()?;
            if !SAFE_IDENTIFIER.is_match(id) {
                return None;
            }
        }
    }
    let prompted_bool = prompted.as_bool()?;
    let reuse_str = reuse.as_str()?;
    if !["not-applicable", "accepted", "rejected"].contains(&reuse_str)
        || (prompted_bool && reuse_str == "accepted")
    {
        return None;
    }
    let (record_id, harness, event) = (record_id.as_str()?, harness.as_str()?, event.as_str()?);
    let (has_command, succeeded) = (has_command.as_bool()?, succeeded.as_bool()?);
    let correlation = match correlation_value {
        None | Some(Value::Null) => None,
        Some(Value::Object(fields)) => Some(CorrelationHandle {
            kind: fields.get("kind")?.as_str()?.to_string(),
            harness: fields.get("harness")?.as_str()?.to_string(),
            key_id: fields.get("key_id")?.as_str()?.to_string(),
            digest: fields.get("digest")?.as_str()?.to_string(),
        }),
        Some(_) => return None,
    };
    let record = CommandActivityRecord {
        record_id: record_id.to_string(),
        harness: harness.to_string(),
        event: event.to_string(),
        correlation,
        has_command,
        succeeded,
        payload_bytes: 0,
        attempts: 0,
        policy_action: policy_action_str.map(str::to_string),
        occurred_at: occurred_at.and_then(Value::as_str).map(str::to_string),
        receipt_id: receipt_id.and_then(Value::as_str).map(str::to_string),
        prompted: prompted_bool,
        approval_reuse_status: reuse_str.to_string(),
        invocation_preview: None,
    };
    let payload_bytes = record.serialized().len();
    // `_attach_invocation_previews`: a recovered record carries the preview
    // its sidecar kept. The journal never writes the key inline, so the
    // serialized bytes this count measures are unaffected.
    let invocation_preview = journal_fs::validated_sidecar_preview(
        value.get("invocation_preview").and_then(Value::as_str),
    );
    Some(CommandActivityRecord {
        payload_bytes,
        invocation_preview,
        ..record
    })
}

// ---------------------------------------------------------------------------
// Stats + the writer (`:56-517`).
// ---------------------------------------------------------------------------

/// `RuntimeHookEvidenceWriterStats` TypedDict (:57-73).
#[derive(Debug, Clone, Default)]
pub struct RuntimeHookEvidenceWriterStats {
    pub queued: usize,
    pub queued_bytes: usize,
    pub accepted: u64,
    pub processed: u64,
    pub dropped: u64,
    pub failures: u64,
    pub recovered: u64,
    pub durable_pending: usize,
    pub degraded: bool,
    pub running: bool,
    pub receipt_accepted: u64,
    pub receipt_processed: u64,
    pub receipt_deduped: u64,
    pub receipt_dropped: u64,
    pub receipt_failures: u64,
    pub receipt_durable_pending: usize,
}

/// Mutable queue state guarded by [`RuntimeHookEvidenceWriter::_condition`].
#[derive(Default)]
struct EvidenceState {
    /// `_records: deque` — pending journal/appends.
    records: VecDeque<EvidenceRecord>,
    /// `_queued_bytes`.
    queued_bytes: usize,
    /// `_durable` — journal-appended awaiting store persistence.
    durable: HashMap<String, EvidenceRecord>,
    /// `_receipt_seen` OrderedDict (insertion-ordered dedupe + LRU eviction).
    receipt_seen: HashSet<String>,
    receipt_seen_order: VecDeque<String>,
    /// `_retry_attempts` — `record_id` → failed attempts, which set the
    /// backoff before the next one.
    retry_attempts: HashMap<String, u32>,
    /// `record_id` → refusals other than a busy store, which alone count
    /// toward [`MAX_STORE_ATTEMPTS`].
    retry_refusals: HashMap<String, u32>,
    /// `record_id` → when a record whose write failed may be tried again.
    /// Records that are not due yet stay queued while the rest move on.
    retry_at: HashMap<String, Instant>,
    /// `_in_flight`.
    in_flight: bool,
    /// `_stopping`.
    stopping: bool,
    /// `_degraded`.
    degraded: bool,
    /// `_drain_deadline` (monotonic).
    drain_deadline: Option<Instant>,
    /// Set once the worker has left its loop, so a stop can wait for the
    /// thread to finish without joining it past its own drain deadline.
    exited: bool,
    accepted: u64,
    processed: u64,
    dropped: u64,
    failures: u64,
    recovered: u64,
    receipt_accepted: u64,
    receipt_processed: u64,
    receipt_deduped: u64,
    receipt_dropped: u64,
    receipt_failures: u64,
}

/// `RuntimeHookEvidenceWriter` (:75-517) — keeps best-effort activity writes
/// outside security-decision workers.
pub struct RuntimeHookEvidenceWriter {
    store: Arc<dyn EvidenceStoreApi + Send + Sync>,
    deps: Arc<EvidenceWriterDeps>,
    guard_home: PathBuf,
    max_records: usize,
    max_bytes: usize,
    max_batch: usize,
    batch_wait_seconds: f64,
    sqlite_timeout_seconds: f64,
    journal_path: PathBuf,
    condition: Arc<(Mutex<EvidenceState>, Condvar)>,
    correlation_key: Mutex<Option<InstallationCorrelationKey>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[allow(dead_code)]
impl RuntimeHookEvidenceWriter {
    /// `__init__` (:75-135). `journal_path` falls back to
    /// `guard_home / "runtime-hook-evidence.jsonl"`.
    pub fn new(
        store: Arc<dyn EvidenceStoreApi + Send + Sync>,
        deps: EvidenceWriterDeps,
        max_records: usize,
        max_bytes: usize,
        max_batch: usize,
        batch_wait_seconds: f64,
        journal_path: Option<PathBuf>,
    ) -> Result<Self, io::Error> {
        if max_records.min(max_bytes).min(max_batch) < 1 || batch_wait_seconds < 0.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime hook evidence writer limits are invalid",
            ));
        }
        let guard_home = store.guard_home();
        let deps = Arc::new(deps);
        let correlation_key = deps
            .correlation
            .load_or_create_installation_correlation_key()
            .ok()
            .flatten();
        let journal_path =
            journal_path.unwrap_or_else(|| guard_home.join("runtime-hook-evidence.jsonl"));
        let writer = Self {
            store,
            deps,
            guard_home,
            max_records,
            max_bytes,
            max_batch,
            batch_wait_seconds,
            sqlite_timeout_seconds: 0.05,
            journal_path,
            condition: Arc::new((Mutex::new(EvidenceState::default()), Condvar::new())),
            correlation_key: Mutex::new(correlation_key),
            thread: Mutex::new(None),
        };
        writer._recover_journal();
        writer._spawn_thread();
        Ok(writer)
    }

    /// `submit_command_activity` (:137-177).
    #[allow(clippy::too_many_arguments)]
    pub fn submit_command_activity(
        &self,
        harness: &str,
        event: &str,
        payload: &Map<String, Value>,
        succeeded: bool,
        policy_action: Option<&str>,
        receipt_id: Option<&str>,
        prompted: bool,
        approval_reuse_status: &str,
    ) -> bool {
        if event == "PreToolUse" && !is_guard_action(&json!(policy_action)) {
            return false;
        }
        let snapshot = payload.clone();
        let mut encoded = Vec::new();
        let Ok(correlation_probe) = (|| -> Result<Option<CorrelationHandle>, io::Error> {
            write_canonical_json_with_limit(
                &Value::Object(snapshot.clone()),
                &mut encoded,
                self.max_bytes,
                "payload too large",
            )
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "payload not JSON-encodable")
            })?;
            let correlation = self._derive_correlation(harness, event, &snapshot)?;
            Ok(correlation)
        })() else {
            self.lock_state().dropped += 1;
            return false;
        };
        let invocation_preview = self
            .deps
            .correlation
            .build_invocation_preview_from_payload(&snapshot)
            .ok()
            .flatten();
        let activity = CommandActivityRecord {
            record_id: uuid4_hex(),
            harness: harness.to_string(),
            event: event.to_string(),
            correlation: correlation_probe,
            has_command: _payload_has_command(&snapshot),
            succeeded,
            payload_bytes: encoded.len(),
            attempts: 0,
            policy_action: policy_action.map(str::to_string),
            occurred_at: Some(utc_now_iso()),
            receipt_id: receipt_id.map(str::to_string),
            prompted,
            approval_reuse_status: approval_reuse_status.to_string(),
            invocation_preview,
        };
        // `_CommandActivityRecord.from_json(json.loads(record.serialized()))
        // is None: return False` (:179-180). The writer admits a record only
        // when its own serialized form parses back, so metadata the journal
        // would refuse on recovery -- an approval reuse that claims both a
        // prompt and an accepted reuse, a malformed receipt id, a policy
        // action on a post event -- is refused here, while the caller is
        // still there to see the submission did not take.
        let round_trip = serde_json::from_slice::<Value>(&activity.serialized());
        let Ok(Value::Object(parsed)) = round_trip else {
            return false;
        };
        if _command_activity_record_from_json(&parsed).is_none() {
            return false;
        }
        let record = EvidenceRecord::CommandActivity(activity);
        let mut state = self.lock_state();
        if state.stopping
            || state.records.len() >= self.max_records
            || state.queued_bytes + record.payload_bytes() > self.max_bytes
        {
            state.dropped += 1;
            state.degraded = true;
            return false;
        }
        state.queued_bytes += record.payload_bytes();
        state.records.push_back(record);
        state.accepted += 1;
        self.condition.1.notify_one();
        true
    }

    /// `submit_composio_discovery` (:178-236).
    pub fn submit_composio_discovery(
        &self,
        harness: &str,
        tool_name: &str,
        payload: &Map<String, Value>,
    ) -> bool {
        let Some(source) = self.deps.composio.observed_mcp_tool(harness, tool_name) else {
            return false;
        };
        let tool_response = payload.get("tool_response").cloned().unwrap_or(Value::Null);
        let Some(actions) = self
            .deps
            .composio
            .composio_discovered_actions(tool_name, &tool_response)
        else {
            return false;
        };
        let proposals = self
            .deps
            .composio
            .composio_workflow_proposals(tool_name, &tool_response)
            .unwrap_or_default();
        let record = EvidenceRecord::McpDiscovery(McpDiscoveryRecord {
            record_id: uuid4_hex(),
            // The record carries the canonical names the lookup resolved, not
            // the caller's spelling: replay re-runs that same lookup and drops
            // a record whose stored harness does not match what it returns.
            harness: source.harness.clone(),
            tool_name: source.qualified_name.clone(),
            occurred_at: utc_now_iso(),
            actions,
            proposals,
            payload_bytes: 0,
            attempts: 0,
        });
        let record = match &record {
            EvidenceRecord::McpDiscovery(inner) => {
                EvidenceRecord::McpDiscovery(McpDiscoveryRecord {
                    payload_bytes: inner.serialized().len(),
                    ..inner.clone()
                })
            }
            _ => unreachable!(),
        };
        let mut state = self.lock_state();
        if state.stopping
            || state.records.len() >= self.max_records
            || state.queued_bytes + record.payload_bytes() > self.max_bytes
        {
            state.dropped += 1;
            state.degraded = true;
            return false;
        }
        state.queued_bytes += record.payload_bytes();
        state.records.push_back(record);
        state.accepted += 1;
        self.condition.1.notify_one();
        true
    }

    /// `submit_native_decision_receipt` (:237-270).
    pub fn submit_native_decision_receipt(&self, receipt: &Map<String, Value>) -> bool {
        let Some(validated) = self.deps.receipts.validate_native_decision_receipt(receipt) else {
            // A receipt that does not validate is a dropped receipt, not a
            // silent no-op: the counters are how a degraded writer is seen.
            let mut state = self.lock_state();
            state.receipt_dropped += 1;
            state.dropped += 1;
            state.degraded = true;
            return false;
        };
        let record = EvidenceRecord::NativeDecisionReceipt(NativeDecisionReceiptRecord {
            receipt: validated,
            payload_bytes: 0,
            attempts: 0,
        });
        let payload_bytes = record.serialized().len();
        let record = match record {
            EvidenceRecord::NativeDecisionReceipt(inner) => {
                EvidenceRecord::NativeDecisionReceipt(NativeDecisionReceiptRecord {
                    payload_bytes,
                    ..inner
                })
            }
            _ => unreachable!(),
        };
        let receipt_id = record.record_id();
        let mut state = self.lock_state();
        if state.receipt_seen.contains(&receipt_id) {
            state.receipt_deduped += 1;
            return true;
        }
        if state.stopping
            || state.records.len() >= self.max_records
            || state.queued_bytes + record.payload_bytes() > self.max_bytes
        {
            state.receipt_dropped += 1;
            state.dropped += 1;
            state.degraded = true;
            return false;
        }
        state.queued_bytes += record.payload_bytes();
        state.records.push_back(record);
        state.receipt_seen.insert(receipt_id.clone());
        state.receipt_seen_order.push_back(receipt_id);
        while state.receipt_seen.len() > self.max_records * 4 {
            if let Some(oldest) = state.receipt_seen_order.pop_front() {
                state.receipt_seen.remove(&oldest);
            } else {
                break;
            }
        }
        state.accepted += 1;
        state.receipt_accepted += 1;
        self.condition.1.notify_one();
        true
    }

    /// `_derive_correlation` (:271-286) — cached install key with single
    /// reload retry on `(OSError, ValueError)`.
    fn _derive_correlation(
        &self,
        harness: &str,
        event: &str,
        payload: &Map<String, Value>,
    ) -> Result<Option<CorrelationHandle>, io::Error> {
        let mut key_guard = self
            .correlation_key
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if key_guard.is_none() {
            *key_guard = self
                .deps
                .correlation
                .load_or_create_installation_correlation_key()?;
        }
        let key_ref = key_guard.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "correlation key unavailable")
        })?;
        match self
            .deps
            .correlation
            .derive_proven_request_correlation(harness, event, payload, key_ref)
        {
            Ok(handle) => Ok(handle),
            Err(err)
                if err.kind() == io::ErrorKind::InvalidInput
                    || err.kind() == io::ErrorKind::Other =>
            {
                *key_guard = self
                    .deps
                    .correlation
                    .load_or_create_installation_correlation_key()?;
                let key_ref = key_guard.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "correlation key unavailable")
                })?;
                self.deps
                    .correlation
                    .derive_proven_request_correlation(harness, event, payload, key_ref)
            }
            Err(err) => Err(err),
        }
    }

    /// `stats()` (:288-311).
    pub fn stats(&self) -> RuntimeHookEvidenceWriterStats {
        let state = self.lock_state();
        RuntimeHookEvidenceWriterStats {
            queued: state.records.len(),
            queued_bytes: state.queued_bytes,
            accepted: state.accepted,
            processed: state.processed,
            dropped: state.dropped,
            failures: state.failures,
            recovered: state.recovered,
            durable_pending: state.durable.len(),
            degraded: state.degraded
                || (!state.durable.is_empty() && state.records.is_empty() && !state.in_flight),
            running: self
                .thread
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
                && !state.stopping,
            receipt_accepted: state.receipt_accepted,
            receipt_processed: state.receipt_processed,
            receipt_deduped: state.receipt_deduped,
            receipt_dropped: state.receipt_dropped,
            receipt_failures: state.receipt_failures,
            receipt_durable_pending: state
                .durable
                .values()
                .filter(|record| record.is_receipt())
                .count(),
        }
    }

    /// `stop` (:313-322) — bounded drain deadline then thread join.
    pub fn stop(&self, timeout_seconds: f64) -> bool {
        let deadline = Instant::now() + Duration::from_secs_f64(timeout_seconds.max(0.0));
        {
            let mut state = self.lock_state();
            state.stopping = true;
            state.drain_deadline = Some(deadline);
            self.condition.1.notify_all();
        }
        let exited = self.wait_for_exit(deadline + WORKER_EXIT_GRACE);
        if exited {
            let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(handle) = thread {
                let _ = handle.join();
            }
        }
        let mut state = self.lock_state();
        if !state.durable.is_empty() {
            state.degraded = true;
        }
        exited
    }

    /// Whether the worker has left its loop. A writer whose worker is gone
    /// queues records nothing will drain, so a caller holding one after an
    /// unfinished stop asks this before using it again.
    pub fn has_exited(&self) -> bool {
        self.lock_state().exited
    }

    /// Whether a stop has been asked of this writer and its worker has not
    /// left the loop yet.
    ///
    /// A worker in this state still owns the journal it is draining, so a
    /// second writer must not be built for the same home until it leaves.
    pub fn is_stopping(&self) -> bool {
        let state = self.lock_state();
        state.stopping && !state.exited
    }

    /// Wait for the worker to leave its loop, and no longer than `deadline`.
    /// The worker honours its drain deadline between records; one blocked in
    /// journal or store I/O cannot, and joining it there would hold the stop
    /// and everything serialised behind it for as long as that write takes.
    fn wait_for_exit(&self, deadline: Instant) -> bool {
        let mut state = self.lock_state();
        loop {
            if state.exited {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (guard, _) = self
                .condition
                .1
                .wait_timeout(state, remaining)
                .unwrap_or_else(|e| e.into_inner());
            state = guard;
        }
    }

    /// `_recover_journal` (:468-490) — replay durable records after restart.
    fn _recover_journal(&self) {
        let recovered = match self
            .deps
            .journal
            .recover_journal_records(&self.journal_path, self.max_bytes)
        {
            Ok(records) => records,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(_) => {
                let mut state = self.lock_state();
                state.degraded = true;
                state.failures += 1;
                return;
            }
        };
        let (raw_records, invalid_records) = recovered;
        let mut state = self.lock_state();
        if invalid_records > 0 {
            state.degraded = true;
            state.failures += invalid_records;
        }
        for raw in raw_records {
            let Some(record) =
                EvidenceRecord::from_json(&raw, &*self.deps.receipts, &*self.deps.composio)
            else {
                state.degraded = true;
                state.failures += 1;
                continue;
            };
            if state.records.len() >= self.max_records
                || state.queued_bytes + record.payload_bytes() > self.max_bytes
            {
                state.degraded = true;
                state.failures += 1;
                continue;
            }
            if record.is_receipt() {
                let receipt_id = record.record_id();
                if state.receipt_seen.contains(&receipt_id) {
                    state.degraded = true;
                    state.failures += 1;
                    continue;
                }
                state.receipt_seen.insert(receipt_id.clone());
                state.receipt_seen_order.push_back(receipt_id);
            }
            state.durable.insert(record.record_id(), record.clone());
            state.queued_bytes += record.payload_bytes();
            state.records.push_back(record);
            state.recovered += 1;
        }
    }

    /// Spawn `hol-guard-hook-evidence` daemon thread running `_run`.
    fn _spawn_thread(&self) {
        // Arc<Self> is unavailable inside `new`; capture the weak pieces.
        let store = Arc::clone(&self.store);
        let deps = Arc::clone(&self.deps);
        let condition = Arc::clone(&self.condition);
        let journal_path = self.journal_path.clone();
        let (max_records, max_bytes, max_batch, batch_wait_seconds, sqlite_timeout) = (
            self.max_records,
            self.max_bytes,
            self.max_batch,
            self.batch_wait_seconds,
            self.sqlite_timeout_seconds,
        );
        let guard_home = self.guard_home.clone();
        let correlation_key = self
            .correlation_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let worker = EvidenceWorker {
            store,
            deps,
            guard_home,
            max_records,
            max_bytes,
            max_batch,
            batch_wait_seconds,
            sqlite_timeout_seconds: sqlite_timeout,
            journal_path,
            condition,
            correlation_key: Mutex::new(correlation_key),
        };
        let handle = std::thread::Builder::new()
            .name("hol-guard-hook-evidence".to_string())
            .spawn(move || worker.run())
            .ok();
        if handle.is_none() {
            // Only the worker's exit marks the state, and this one never
            // started. Left alone, the writer would look live for the rest of
            // the process: submissions would queue onto a deque nothing
            // drains, and the slot would never replace it. It is marked
            // stopping so submissions are refused rather than lost, and
            // exited so the next request builds a writer that runs.
            let mut state = self.lock_state();
            state.stopping = true;
            state.exited = true;
            state.degraded = true;
            self.condition.1.notify_all();
        }
        *self.thread.lock().unwrap_or_else(|e| e.into_inner()) = handle;
    }

    /// Lock the shared condition state, recovering from poisoning.
    fn lock_state(&self) -> MutexGuard<'_, EvidenceState> {
        self.condition.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Per-record persist result inside `_run`.
pub(crate) enum PersistOutcome {
    Done,
    Deduped,
    /// The write failed for a reason a later attempt may not fix. It is
    /// retried at most [`MAX_STORE_ATTEMPTS`] times.
    Retry,
    /// Another writer held the store past this one's lock budget. The record
    /// stays journaled and is retried until the store frees up or a stop
    /// leaves it for the next writer.
    Busy,
}

/// How a store error is retried: a lock the store or its storage gate timed
/// out on is waited out, anything else is retried a bounded number of times.
pub(crate) fn store_refused(error: &io::Error) -> PersistOutcome {
    if error.kind() == io::ErrorKind::TimedOut {
        PersistOutcome::Busy
    } else {
        PersistOutcome::Retry
    }
}

/// `hashlib.sha256(json.dumps([...]).encode("utf-8")).hexdigest()` over the
/// prevented-attempt tuple.
///
/// `json.dumps` writes `", "` between elements, so the parts are joined that
/// way rather than with `serde_json`'s compact separator; the digest is a join
/// key and both runtimes have to land on the same bytes.
fn prevented_attempt_digest(
    correlation: &CorrelationHandle,
    record: &CommandActivityRecord,
    policy_action: &str,
) -> String {
    let parts = [
        Value::from("native-prevented-attempt-v1"),
        Value::from(correlation.digest.as_str()),
        Value::from(policy_action),
        record
            .receipt_id
            .as_deref()
            .map_or(Value::Null, Value::from),
        Value::from(record.prompted),
        Value::from(record.approval_reuse_status.as_str()),
    ];
    let rendered: Vec<String> = parts.iter().map(Value::to_string).collect();
    let encoded = format!("[{}]", rendered.join(", "));
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

/// Worker half of [`RuntimeHookEvidenceWriter`] — owns `_run` on its thread
/// without an `Arc<Self>` cycle.
#[allow(dead_code)]
struct EvidenceWorker {
    store: Arc<dyn EvidenceStoreApi + Send + Sync>,
    deps: Arc<EvidenceWriterDeps>,
    #[allow(dead_code)]
    guard_home: PathBuf,
    max_records: usize,
    max_bytes: usize,
    max_batch: usize,
    batch_wait_seconds: f64,
    sqlite_timeout_seconds: f64,
    journal_path: PathBuf,
    condition: Arc<(Mutex<EvidenceState>, Condvar)>,
    correlation_key: Mutex<Option<InstallationCorrelationKey>>,
}

/// Reports the worker's exit to a stop waiting on it, however the loop ends.
struct WorkerExit {
    condition: Arc<(Mutex<EvidenceState>, Condvar)>,
}

impl Drop for WorkerExit {
    fn drop(&mut self) {
        let mut state = self.condition.0.lock().unwrap_or_else(|e| e.into_inner());
        state.exited = true;
        self.condition.1.notify_all();
    }
}

impl EvidenceWorker {
    /// `_run` (:324-453).
    fn run(&self) {
        let _exit = WorkerExit {
            condition: Arc::clone(&self.condition),
        };
        loop {
            let batch = self.next_batch();
            if batch.is_empty() {
                return;
            }
            for record in batch {
                self.lock_state().in_flight = true;
                let already_durable = self.lock_state().durable.contains_key(&record.record_id());
                if !already_durable {
                    if self
                        .deps
                        .journal
                        .append_journal(&self.journal_path, &record)
                        .is_err()
                    {
                        let mut state = self.lock_state();
                        state.dropped += 1;
                        state.failures += 1;
                        if record.is_receipt() {
                            state.receipt_dropped += 1;
                            state.receipt_failures += 1;
                        }
                        state.degraded = true;
                        state.in_flight = false;
                        continue;
                    }
                    self.lock_state()
                        .durable
                        .insert(record.record_id(), record.clone());
                }
                {
                    let mut state = self.lock_state();
                    if state.stopping
                        && state
                            .drain_deadline
                            .is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        state.degraded = true;
                        state.in_flight = false;
                        continue;
                    }
                }
                let outcome = match &record {
                    EvidenceRecord::CommandActivity(command_record) => {
                        self.persist_command_activity(command_record)
                    }
                    EvidenceRecord::McpDiscovery(discovery_record) => {
                        self.persist_mcp_discovery(discovery_record)
                    }
                    EvidenceRecord::NativeDecisionReceipt(receipt_record) => {
                        self.persist_native_decision_receipt(receipt_record)
                    }
                };
                let mut state = self.lock_state();
                match outcome {
                    PersistOutcome::Done => {
                        let _ = state.durable.remove(&record.record_id());
                        state.retry_attempts.remove(&record.record_id());
                        state.retry_at.remove(&record.record_id());
                        state.retry_refusals.remove(&record.record_id());
                        if record.is_receipt() {
                            state.receipt_processed += 1;
                        }
                        state.processed += 1;
                        match self.rewrite_journal(&record.record_id()) {
                            Ok(invalid_records) => {
                                if invalid_records > 0 {
                                    state.failures += invalid_records;
                                    state.degraded = true;
                                }
                            }
                            Err(_) => {
                                state.failures += 1;
                                state.degraded = true;
                            }
                        }
                    }
                    PersistOutcome::Deduped => {
                        let _ = state.durable.remove(&record.record_id());
                        state.retry_attempts.remove(&record.record_id());
                        state.retry_at.remove(&record.record_id());
                        state.retry_refusals.remove(&record.record_id());
                        if record.is_receipt() {
                            state.receipt_deduped += 1;
                        }
                        match self.rewrite_journal(&record.record_id()) {
                            Ok(invalid_records) => {
                                if invalid_records > 0 {
                                    state.failures += invalid_records;
                                    state.degraded = true;
                                }
                            }
                            Err(_) => {
                                state.failures += 1;
                                state.degraded = true;
                            }
                        }
                    }
                    outcome @ (PersistOutcome::Retry | PersistOutcome::Busy) => {
                        // A failed write is most often another writer holding
                        // the store for longer than this one's short lock
                        // budget. The record is already in the journal, so it
                        // goes to the back of the queue and waits out a
                        // backoff while the records behind it keep moving. A
                        // stop that runs out of drain time leaves it for the
                        // next writer to replay. Only a record the store
                        // refused for another reason on every attempt is
                        // dropped and cleared from the journal.
                        let record_id = record.record_id();
                        let attempt = state
                            .retry_attempts
                            .get(&record_id)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(1);
                        state.failures += 1;
                        if record.is_receipt() {
                            state.receipt_failures += 1;
                        }
                        state.degraded = true;
                        // Every failure lengthens the backoff, but only a
                        // refusal other than a busy store spends an attempt.
                        let refusals = state.retry_refusals.get(&record_id).copied().unwrap_or(0)
                            + u32::from(matches!(outcome, PersistOutcome::Retry));
                        if refusals >= MAX_STORE_ATTEMPTS {
                            let _ = state.durable.remove(&record_id);
                            state.retry_attempts.remove(&record_id);
                            state.retry_at.remove(&record_id);
                            state.retry_refusals.remove(&record_id);
                            state.dropped += 1;
                            if record.is_receipt() {
                                state.receipt_dropped += 1;
                            }
                            match self.rewrite_journal(&record_id) {
                                Ok(invalid_records) => state.failures += invalid_records,
                                Err(_) => state.failures += 1,
                            }
                        } else {
                            if refusals > 0 {
                                state.retry_refusals.insert(record_id.clone(), refusals);
                            }
                            state.retry_attempts.insert(record_id.clone(), attempt);
                            state
                                .retry_at
                                .insert(record_id, Instant::now() + retry_backoff(attempt));
                            state.queued_bytes += record.payload_bytes();
                            state.records.push_back(record.clone());
                        }
                    }
                }
                state.in_flight = false;
            }
        }
    }

    /// `_next_batch` (:454-463).
    ///
    /// Only records that are due go into a batch: one waiting out a retry
    /// backoff keeps its place in the queue. With nothing due the worker
    /// sleeps until the first retry is due, a submission arrives or a stop
    /// asks it to drain, and never past the stop's drain deadline.
    fn next_batch(&self) -> Vec<EvidenceRecord> {
        let mut state = self.lock_state();
        loop {
            let now = Instant::now();
            let drain_over =
                state.stopping && state.drain_deadline.is_none_or(|deadline| now >= deadline);
            if drain_over
                || state
                    .records
                    .iter()
                    .any(|record| is_due(&state, record, now))
            {
                break;
            }
            if state.records.is_empty() {
                if state.stopping {
                    break;
                }
                state = self
                    .condition
                    .1
                    .wait(state)
                    .unwrap_or_else(|e| e.into_inner());
                continue;
            }
            let mut wake = state
                .records
                .iter()
                .filter_map(|record| state.retry_at.get(&record.record_id()).copied())
                .min()
                .unwrap_or(now);
            if let Some(deadline) = state.drain_deadline.filter(|_| state.stopping) {
                wake = wake.min(deadline);
            }
            let (guard, _) = self
                .condition
                .1
                .wait_timeout(state, wake.saturating_duration_since(now))
                .unwrap_or_else(|e| e.into_inner());
            state = guard;
        }
        if state.records.is_empty() {
            return Vec::new();
        }
        if !state.stopping && self.batch_wait_seconds > 0.0 {
            let (guard, _) = self
                .condition
                .1
                .wait_timeout(state, Duration::from_secs_f64(self.batch_wait_seconds))
                .unwrap_or_else(|e| e.into_inner());
            state = guard;
        }
        // Once a stop's drain time is over, every record is handed back so
        // the worker can leave each one in the journal and exit.
        let now = Instant::now();
        let take_all =
            state.stopping && state.drain_deadline.is_none_or(|deadline| now >= deadline);
        let mut batch = Vec::new();
        let mut waiting = VecDeque::new();
        while let Some(record) = state.records.pop_front() {
            if batch.len() >= self.max_batch {
                state.records.push_front(record);
                break;
            }
            if !take_all && !is_due(&state, &record, now) {
                waiting.push_back(record);
                continue;
            }
            state.queued_bytes = state.queued_bytes.saturating_sub(record.payload_bytes());
            batch.push(record);
        }
        while let Some(record) = waiting.pop_back() {
            state.records.push_front(record);
        }
        batch
    }

    /// `_persist_command_activity` (:410-455) under `sqlite_timeout_override`.
    ///
    /// A Pre event carries the whole verdict already: Rust built the evidence,
    /// so the store writes it and never recomputes it. Every other event is a
    /// post observation and goes through the deferred pairing helper.
    fn persist_command_activity(&self, record: &CommandActivityRecord) -> PersistOutcome {
        let _timeout_guard = self.deps.sqlite_timeout.sqlite_timeout_override(
            NonZeroU32::new((self.sqlite_timeout_seconds * 1000.0).ceil().max(1.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        );
        if record.event != "PreToolUse" {
            return persist_deferred_post_hook_command_activity(
                self.store.as_ref(),
                self.deps.as_ref(),
                record,
            );
        }
        let (Some(policy_action), Some(occurred_at)) = (
            record.policy_action.as_deref(),
            record.occurred_at.as_deref(),
        ) else {
            return PersistOutcome::Done;
        };
        if !record.has_command {
            return PersistOutcome::Done;
        }
        // A prevented attempt cannot produce a post event. Keep its evidence
        // separate from a later approved retry of the same call.
        let correlation = record.correlation.as_ref().map(|correlation| {
            if matches!(policy_action, "allow" | "warn") {
                correlation.clone()
            } else {
                CorrelationHandle {
                    digest: prevented_attempt_digest(correlation, record, policy_action),
                    ..correlation.clone()
                }
            }
        });
        let evidence = match self.deps.correlation.build_policy_only_pre_hook_evidence(
            record.record_id(),
            occurred_at,
            &record.harness,
            policy_action,
            correlation.as_ref(),
            record.receipt_id.as_deref(),
            record.prompted,
            &record.approval_reuse_status,
        ) {
            Ok(evidence) => evidence,
            Err(_) => return PersistOutcome::Retry,
        };
        match self.store.is_exact_command_activity_pre_replay(&evidence) {
            Ok(true) => return PersistOutcome::Done,
            Ok(false) => {}
            Err(error) => return store_refused(&error),
        }
        match self
            .store
            .record_command_activity(&evidence, record.invocation_preview.as_deref())
        {
            Ok(_) => PersistOutcome::Done,
            Err(error) => store_refused(&error),
        }
    }

    /// `_persist_mcp_discovery` (:407-413).
    fn persist_mcp_discovery(&self, record: &McpDiscoveryRecord) -> PersistOutcome {
        let Some(source) = self
            .deps
            .composio
            .observed_mcp_tool(&record.harness, &record.tool_name)
        else {
            return PersistOutcome::Done;
        };
        let _timeout_guard = self.deps.sqlite_timeout.sqlite_timeout_override(
            NonZeroU32::new((self.sqlite_timeout_seconds * 1000.0).ceil().max(1.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        );
        match self.store.record_composio_discovery(
            &source,
            &record.actions,
            &record.occurred_at,
            &record.proposals,
        ) {
            Ok(()) => PersistOutcome::Done,
            Err(error) => store_refused(&error),
        }
    }

    /// `_persist_native_decision_receipt` (:414-428).
    fn persist_native_decision_receipt(
        &self,
        record: &NativeDecisionReceiptRecord,
    ) -> PersistOutcome {
        let _timeout_guard = self.deps.sqlite_timeout.sqlite_timeout_override(
            NonZeroU32::new((self.sqlite_timeout_seconds * 1000.0).ceil().max(1.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        );
        match self.store.record_native_decision_receipt(&record.receipt) {
            Ok(true) => PersistOutcome::Done,
            Ok(false) => PersistOutcome::Deduped,
            Err(error) => store_refused(&error),
        }
    }

    /// `_rewrite_journal` (:496-502).
    /// Rewrite the journal without the record, and report how many invalid
    /// lines the rewrite dropped.
    ///
    /// The count is returned rather than recorded here. Every caller runs
    /// inside the worker loop holding the shared state, and this lock is not
    /// reentrant: taking it again on the same thread would wedge the worker
    /// while it holds the lock a stop needs, and every request behind that
    /// stop with it.
    fn rewrite_journal(&self, remove_record_id: &str) -> Result<u64, io::Error> {
        self.deps
            .journal
            .rewrite_journal(&self.journal_path, remove_record_id, self.max_bytes)
    }

    fn lock_state(&self) -> MutexGuard<'_, EvidenceState> {
        self.condition.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `uuid4().hex` — 32 lowercase hex characters.
fn uuid4_hex() -> String {
    let mut bytes = [0u8; 16];
    let mut filled = 0usize;
    while filled < bytes.len() {
        match std::fs::File::open("/dev/urandom") {
            Ok(mut file) => {
                use std::io::Read;
                if file.read_exact(&mut bytes[filled..]).is_ok() {
                    filled = bytes.len();
                } else {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `persist_native_decision_receipt` (:47-53). Persist a validated receipt
/// through the control-plane store only. `recorder` absence raises
/// `RuntimeError` in Python → `Err(Unsupported)` here.
pub fn persist_native_decision_receipt(
    store: &dyn EvidenceStoreApi,
    receipt: &Map<String, Value>,
) -> Result<bool, io::Error> {
    let result = store.record_native_decision_receipt(receipt)?;
    Ok(result)
}

/// Convenience alias kept for parity with `__all__`.
pub type EvidenceJournalFileMode = u32;

/// Exposed for the `0o600` append mode parity note.
pub const fn journal_file_mode() -> u32 {
    JOURNAL_FILE_MODE
}

#[path = "hook_evidence_journal_fs.rs"]
mod journal_fs;

pub use journal_fs::NativeEvidenceJournal;

#[path = "hook_evidence_receipt.rs"]
mod receipt;

pub use receipt::{
    canonical_receipt_bytes, valid_prompt_risk_classes, validate_native_decision_receipt,
    NativeReceiptValidation,
};

#[path = "hook_evidence_preview.rs"]
mod preview;

pub use preview::{
    build_invocation_preview, build_invocation_preview_from_payload, checked_command_from_payload,
    INVOCATION_PREVIEW_MAX_CHARS,
};
