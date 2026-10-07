//! Port of `src/codex_plugin_scanner/guard/inventory_contract.py`
//! (8 fns) plus `inventory_contract_scans.py` (8 fns) — RTM-027.
//!
//! Public inventory API: contract JSON serialization, cloud-artifact
//! projection, AIBOM metadata extraction, and snapshot assembly.
//!
//! TODO(deps): the Python module lazily resolves
//! `.inventory_contract_items` (`_item_from_artifact`,
//! `_mcp_tool_items_from_artifact`), `.inventory_contract_metadata`
//! (`_aibom_detection_module`), `.inventory_contract_redaction`
//! (`_redact_known_path`, `_safe_finding_text`, `_safe_source_detail`,
//! `_safe_json`, `_assert_serialized_inventory_payload_safe`),
//! `.inventory_contract_fingerprints` (`fingerprint_text`,
//! `fingerprint_mapping`, `inventory_item_id`,
//! `_inventory_snapshot_content_hash`), `.inventory_agent_types`
//! (`_agent_type`, `AgentInventoryType`), and `.inventory_contract_constants`
//! for all record-key sets. Until those land they sit behind the
//! `InventoryContractApi` + `RedactionApi` + `FingerprintApi` +
//! `AgentTypeApi` + `ItemProjectionApi` seams; `_normalize_inventory_datetime`
//! is mirrored locally (shared with `aibom_trust_metadata`).

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::aibom_trust_metadata::normalize_inventory_datetime;

// ---------------------------------------------------------------------------
// Model mirrors (`inventory_contract_models` dataclasses → structs).
// ---------------------------------------------------------------------------

/// `GuardAgentInventoryItem` mirror — the fields read by the contract/scans
/// helpers ported here.
#[derive(Debug, Clone, Default)]
pub struct GuardAgentInventoryItem {
    pub item_id: String,
    pub item_kind: String,
    pub display_name: String,
    pub metadata: Map<String, Value>,
    pub capability_categories: Vec<String>,
    pub content_hash: String,
    pub drift_state: String,
    /// Remaining dataclass fields ride along verbatim.
    pub extra: Map<String, Value>,
}

/// `GuardAgentInventoryFinding` mirror.
#[derive(Debug, Clone, Default)]
pub struct GuardAgentInventoryFinding {
    pub finding_id: String,
    pub source: String,
    pub severity: String,
    pub confidence: String,
    pub title: String,
    pub artifact_id: String,
    pub check_id: String,
    pub summary: String,
    pub evidence: Map<String, Value>,
    /// Remaining dataclass fields.
    pub extra: Map<String, Value>,
}

/// `GuardInventorySource` mirror.
#[derive(Debug, Clone, Default)]
pub struct GuardInventorySource {
    pub source_id: String,
    pub source_type: String,
    pub status: String,
    pub detail: String,
    pub captured_at: String,
    /// Remaining dataclass fields.
    pub extra: Map<String, Value>,
}

/// `GuardAgentInventorySnapshot` mirror.
#[derive(Debug, Clone, Default)]
pub struct GuardAgentInventorySnapshot {
    pub snapshot_id: String,
    pub agent_id: String,
    pub agent_type: String,
    pub generated_at: String,
    pub runtime_version: String,
    pub items: Vec<GuardAgentInventoryItem>,
    pub findings: Vec<GuardAgentInventoryFinding>,
    pub sources: Vec<GuardInventorySource>,
    pub redaction_report: Map<String, Value>,
    /// Remaining dataclass fields.
    pub extra: Map<String, Value>,
}

/// `GuardAgentIntegrationRun` (`run`) mirror — duck-typed JSON object carrying
/// `source`, `status`, `message`, `duration_ms`, `findings`, `metadata`.
pub type CiscoRun = Map<String, Value>;

/// `CloudInventoryDetection` mirror — duck-typed `getattr` object → `Map`.
pub type CloudInventoryDetection = Map<String, Value>;

/// `GuardLocalArtifact` (`artifact`) mirror — duck-typed `getattr` object →
/// `Map`.
pub type LocalArtifact = Map<String, Value>;

/// `InventoryFindingSource` Literal — newtype for source tokens.
pub type InventoryFindingSource = &'static str;

/// `InventorySeverity` Literal — newtype for severity tokens.
pub type InventorySeverity = &'static str;

/// `SyncSummary` mirror — duck-typed `getattr` object → `Map`.
pub type SyncSummary = Map<String, Value>;

// ---------------------------------------------------------------------------
// Dependency seams.
// ---------------------------------------------------------------------------

/// `.inventory_contract_redaction` seam.
pub trait InventoryRedactionApi {
    /// `redact_local_path(path, *, home_dir=None)` — when `home_dir` is `None`
    /// the Python default resolution applies.
    fn redact_local_path(&self, path: &Path, home_dir: Option<&Path>) -> String;
    /// `_redact_known_path(value, home_dir, workspace_dir)`
    fn _redact_known_path(
        &self,
        value: &str,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
    ) -> String;
    /// `_safe_finding_text(value, *, home_dir, workspace_dir)`
    fn _safe_finding_text(
        &self,
        value: &str,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
    ) -> String;
    /// `_safe_source_detail(run)` — `run` is a duck-typed JSON object.
    fn _safe_source_detail(&self, run: &Map<String, Value>) -> String;
    /// `_safe_json(value, *, parent_key="", parent_sensitive=False)`
    fn _safe_json(&self, value: &Value, parent_key: &str, parent_sensitive: bool) -> Value;
    /// `_assert_serialized_inventory_payload_safe(payload)`
    fn _assert_serialized_inventory_payload_safe(&self, payload: &Value) -> Result<(), String>;
}

/// `.inventory_contract_fingerprints` seam.
pub trait FingerprintApi {
    /// `fingerprint_text(value)`
    fn fingerprint_text(&self, value: &str) -> String;
    /// `fingerprint_mapping(value)` — deterministic JSON → sha256.
    fn fingerprint_mapping(&self, value: &Value) -> String;
    /// `inventory_item_id(agent_type, item_kind, display_name, semantic_text)`
    fn inventory_item_id(
        &self,
        agent_type: &str,
        item_kind: &str,
        display_name: &str,
        semantic_text: &str,
    ) -> String;
    /// `_inventory_snapshot_content_hash(*, agent_type, items, findings, sources, runtime_version)`
    fn _inventory_snapshot_content_hash(
        &self,
        agent_type: &str,
        items: &[GuardAgentInventoryItem],
        findings: &[GuardAgentInventoryFinding],
        sources: &[GuardInventorySource],
        runtime_version: Option<&str>,
    ) -> String;
}

/// `.inventory_agent_types` seam.
pub trait AgentTypeApi {
    /// `agent_type(agent_id)` → `AgentInventoryType`.
    fn _agent_type(&self, agent_id: &str) -> String;
}

/// `.inventory_contract_items` + `.inventory_contract_metadata` seam.
pub trait ItemProjectionApi {
    /// `_item_from_artifact(harness, artifact, *, generated_at, home_dir,
    /// workspace_dir, cisco_runs, include_symlinks, follow_unsafe_symlinks,
    /// trust_attestation_context)`
    #[allow(clippy::too_many_arguments)]
    fn _item_from_artifact(
        &self,
        harness: &str,
        artifact: &LocalArtifact,
        generated_at: &str,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
        cisco_runs: &[CiscoRun],
        include_symlinks: bool,
        follow_unsafe_symlinks: bool,
        trust_attestation_context: Option<&Map<String, Value>>,
    ) -> GuardAgentInventoryItem;
    /// `_mcp_tool_items_from_artifact(harness, artifact, item, *,
    /// generated_at, home_dir, workspace_dir, cisco_runs,
    /// trust_attestation_context)`
    #[allow(clippy::too_many_arguments)]
    fn _mcp_tool_items_from_artifact(
        &self,
        harness: &str,
        artifact: &LocalArtifact,
        item: &GuardAgentInventoryItem,
        generated_at: &str,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
        cisco_runs: &[CiscoRun],
        trust_attestation_context: Option<&Map<String, Value>>,
    ) -> Vec<GuardAgentInventoryItem>;
    /// `_aibom_detection_module().discover_shared_workspace_aibom_artifacts(
    ///     harness, *, home_dir, workspace_dir)`
    fn discover_shared_workspace_aibom_artifacts(
        &self,
        harness: &str,
        home_dir: &Path,
        workspace_dir: &Path,
    ) -> Vec<LocalArtifact>;
}

/// Bundled seams — one `impl` reference per public function.
pub struct InventoryDeps<'a> {
    pub redaction: &'a dyn InventoryRedactionApi,
    pub fingerprint: &'a dyn FingerprintApi,
    pub agent_type: &'a dyn AgentTypeApi,
    pub items: &'a dyn ItemProjectionApi,
}

// ---------------------------------------------------------------------------
// Constants (`inventory_contract_constants`).
// ---------------------------------------------------------------------------

/// `_AIBOM_METADATA_KEYS` — keys extracted verbatim into AIBOM metadata.
pub static AIBOM_METADATA_KEYS: &[&str] = &[
    "instructionRole",
    "localSecurity",
    "registryIdentity",
    "skillDirectoryIdentity",
    "sourceLinks",
    "sourceOfTruth",
    "trustLayers",
    "trustResolution",
    "unverifiedAdapterEvidence",
    "versionInfo",
];

/// `_FREE_FORM_RECORD_KEYS` — passthrough metadata keys.
pub static FREE_FORM_RECORD_KEYS: &[&str] = &["metadata", "evidence"];

/// `_INVENTORY_DATETIME_KEYS` — fields normalized through
/// `_normalize_inventory_datetime`.
pub static INVENTORY_DATETIME_KEYS: &[&str] = &[
    "capturedAt",
    "completedAt",
    "firstSeenAt",
    "generatedAt",
    "lastSeenAt",
    "startedAt",
];

/// `_OPTIONAL_ONLY_CONTRACT_KEYS` — AIBOM metadata keys emitted only when set.
pub static OPTIONAL_ONLY_CONTRACT_KEYS: &[&str] = &["summary"];

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

fn a_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// Recursive mirror of Python `_inventory_contract_json` for a single `Value`.
///
/// Python serializes the whole `asdict(snapshot)` payload through this walker:
/// every dict key is snake→camel cased, `None` values under
/// `_OPTIONAL_ONLY_CONTRACT_KEYS` are dropped, `metadata`/`evidence` records and
/// `redactionReport` pass through untouched (the caller already normalizes the
/// report), every `_INVENTORY_DATETIME_KEYS` field is normalized, and all other
/// values recurse. The per-entity builders below emit their named fields
/// explicitly; `extra` free-form fields ride through this walker verbatim.
fn contract_value_json(key_camel: &str, value: &Value) -> Option<Value> {
    if value.is_null() && OPTIONAL_ONLY_CONTRACT_KEYS.contains(&key_camel) {
        return None;
    }
    if FREE_FORM_RECORD_KEYS.contains(&key_camel) || key_camel == "redactionReport" {
        return Some(value.clone());
    }
    if INVENTORY_DATETIME_KEYS.contains(&key_camel) {
        return Some(normalize_inventory_datetime(value));
    }
    Some(match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let camel = _snake_to_camel_case_key(k);
                if let Some(normalized) = contract_value_json(&camel, v) {
                    out.insert(camel, normalized);
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| contract_value_json("", item).unwrap_or_else(|| item.clone()))
                .collect(),
        ),
        _ => value.clone(),
    })
}

/// `getattr(run, key)` → non-empty `str`.
fn run_str<'a>(run: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    run.get(key).and_then(Value::as_str)
}

fn run_findings(run: &Map<String, Value>) -> &[Value] {
    run.get("findings")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

// ---------------------------------------------------------------------------
// `inventory_contract.py` — defmap order.
// ---------------------------------------------------------------------------

/// `_snake_to_camel_case_key(key)`
pub fn _snake_to_camel_case_key(key: &str) -> String {
    if !key.contains('_') {
        return key.to_string();
    }
    let mut parts = key.split('_');
    let head = parts.next().unwrap_or("");
    let mut out = head.to_string();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    out
}

/// `_normalize_redaction_report(report)`
pub fn _normalize_redaction_report(report: &Value) -> Map<String, Value> {
    let report_obj = match report.as_object() {
        Some(r) => r,
        None => {
            let mut out = Map::new();
            out.insert("rawSecretsIncluded".into(), json!(false));
            out.insert("redactedFields".into(), json!([]));
            return out;
        }
    };
    let raw_secrets = report_obj
        .get("rawSecretsIncluded")
        .or_else(|| report_obj.get("raw_secret_values"))
        .or_else(|| report_obj.get("raw_secrets_included"))
        .cloned()
        .unwrap_or(json!(false));
    let redacted_fields = report_obj
        .get("redactedFields")
        .or_else(|| report_obj.get("redacted_fields"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Map::new();
    out.insert(
        "rawSecretsIncluded".into(),
        json!(raw_secrets.as_bool() == Some(true)),
    );
    out.insert("redactedFields".into(), Value::Array(redacted_fields));
    out
}

/// `_normalize_inventory_datetime(value)` — re-exported local mirror.
pub fn _normalize_inventory_datetime(value: &Value) -> Value {
    normalize_inventory_datetime(value)
}

/// `_inventory_contract_json(snapshot, *, include_symlinks=True)`
pub fn _inventory_contract_json(
    snapshot: &GuardAgentInventorySnapshot,
    deps: &InventoryDeps<'_>,
    include_symlinks: bool,
) -> Map<String, Value> {
    let items_json: Vec<Value> = snapshot
        .items
        .iter()
        .map(|item| _inventory_item_json(item, deps, include_symlinks))
        .collect();
    let findings_json: Vec<Value> = snapshot
        .findings
        .iter()
        .map(_inventory_finding_json)
        .collect();
    let sources_json: Vec<Value> = snapshot
        .sources
        .iter()
        .map(_inventory_source_json)
        .collect();
    let mut out = Map::new();
    out.insert("snapshotId".into(), json!(snapshot.snapshot_id));
    out.insert("agentId".into(), json!(snapshot.agent_id));
    out.insert("agentType".into(), json!(snapshot.agent_type));
    out.insert(
        "generatedAt".into(),
        normalize_inventory_datetime(&json!(snapshot.generated_at)),
    );
    out.insert("runtimeVersion".into(), json!(snapshot.runtime_version));
    out.insert("items".into(), Value::Array(items_json));
    out.insert("findings".into(), Value::Array(findings_json));
    out.insert("sources".into(), Value::Array(sources_json));
    out.insert(
        "redactionReport".into(),
        Value::Object(_normalize_redaction_report(&Value::Object(
            snapshot.redaction_report.clone(),
        ))),
    );
    for (k, v) in &snapshot.extra {
        let camel = _snake_to_camel_case_key(k);
        if let Some(normalized) = contract_value_json(&camel, v) {
            out.insert(camel, normalized);
        }
    }
    out
}

fn _inventory_item_json(
    item: &GuardAgentInventoryItem,
    deps: &InventoryDeps<'_>,
    include_symlinks: bool,
) -> Value {
    let mut metadata = item.metadata.clone();
    if !include_symlinks {
        metadata.remove("sourceOfTruth");
        metadata.remove("sourceLinks");
    }
    let mut obj = Map::new();
    obj.insert("itemId".into(), json!(item.item_id));
    obj.insert("itemKind".into(), json!(item.item_kind));
    obj.insert("displayName".into(), json!(item.display_name));
    obj.insert(
        "capabilityCategories".into(),
        json!(item.capability_categories),
    );
    obj.insert("contentHash".into(), json!(item.content_hash));
    obj.insert("driftState".into(), json!(item.drift_state));
    obj.insert(
        "metadata".into(),
        deps.redaction
            ._safe_json(&Value::Object(metadata), "", false),
    );
    for (k, v) in &item.extra {
        let camel = _snake_to_camel_case_key(k);
        if let Some(normalized) = contract_value_json(&camel, v) {
            obj.insert(camel, normalized);
        }
    }
    Value::Object(obj)
}

fn _inventory_finding_json(finding: &GuardAgentInventoryFinding) -> Value {
    let mut obj = Map::new();
    obj.insert("findingId".into(), json!(finding.finding_id));
    obj.insert("source".into(), json!(finding.source));
    obj.insert("severity".into(), json!(finding.severity));
    obj.insert("confidence".into(), json!(finding.confidence));
    obj.insert("title".into(), json!(finding.title));
    obj.insert("artifactId".into(), json!(finding.artifact_id));
    obj.insert("checkId".into(), json!(finding.check_id));
    obj.insert("summary".into(), json!(finding.summary));
    obj.insert("evidence".into(), Value::Object(finding.evidence.clone()));
    for (k, v) in &finding.extra {
        let camel = _snake_to_camel_case_key(k);
        if let Some(normalized) = contract_value_json(&camel, v) {
            obj.insert(camel, normalized);
        }
    }
    Value::Object(obj)
}

fn _inventory_source_json(source: &GuardInventorySource) -> Value {
    // Python `asdict(GuardInventorySource)` emits `captured_at`/`detail` as
    // `None` when unset and `_inventory_contract_json` keeps them in dataclass
    // field order (source_id, source_type, status, captured_at, detail). Mirror
    // that: always emit both keys, `null` for empty, `capturedAt` before
    // `detail`, and run both through `_normalize_inventory_datetime`.
    let mut obj = Map::new();
    obj.insert("sourceId".into(), json!(source.source_id));
    obj.insert("sourceType".into(), json!(source.source_type));
    obj.insert("status".into(), json!(source.status));
    obj.insert(
        "capturedAt".into(),
        if source.captured_at.is_empty() {
            Value::Null
        } else {
            normalize_inventory_datetime(&json!(source.captured_at))
        },
    );
    obj.insert(
        "detail".into(),
        if source.detail.is_empty() {
            Value::Null
        } else {
            json!(source.detail)
        },
    );
    for (k, v) in &source.extra {
        let camel = _snake_to_camel_case_key(k);
        if let Some(normalized) = contract_value_json(&camel, v) {
            obj.insert(camel, normalized);
        }
    }
    Value::Object(obj)
}

/// `serialize_inventory_snapshot(snapshot, *, include_symlinks=True)` → wire str.
pub fn serialize_inventory_snapshot(
    snapshot: &GuardAgentInventorySnapshot,
    deps: &InventoryDeps<'_>,
    include_symlinks: bool,
) -> Result<String, String> {
    let payload = _inventory_contract_json(snapshot, deps, include_symlinks);
    let payload_value = Value::Object(payload);
    deps.redaction
        ._assert_serialized_inventory_payload_safe(&payload_value)?;
    // `json.dumps(payload, sort_keys=True, separators=(",", ":"))`
    serde_json::to_string(&payload_value).map_err(|e| e.to_string())
}

/// `extract_aibom_metadata_extensions(metadata)`
pub fn extract_aibom_metadata_extensions(
    metadata: &Map<String, Value>,
    deps: &InventoryDeps<'_>,
) -> Map<String, Value> {
    let mut extensions = Map::new();
    for key in AIBOM_METADATA_KEYS {
        if let Some(value) = metadata.get(*key) {
            extensions.insert(
                (*key).to_string(),
                deps.redaction._safe_json(value, "", false),
            );
        }
    }
    if !extensions.contains_key("sourceLinks") {
        if let Some(source_of_truth) = extensions.get("sourceOfTruth").and_then(Value::as_object) {
            extensions.insert(
                "sourceLinks".into(),
                Value::Array(vec![deps.redaction._safe_json(
                    &Value::Object(source_of_truth.clone()),
                    "",
                    false,
                )]),
            );
        }
    }
    extensions
}

/// `cloud_inventory_artifacts_from_detection(detection, *, home_dir, workspace_dir=None)`
pub fn cloud_inventory_artifacts_from_detection(
    detection: &CloudInventoryDetection,
    deps: &InventoryDeps<'_>,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> Vec<LocalArtifact> {
    let harness = a_str(detection, "harness").unwrap_or("unknown").to_string();
    let mut artifacts: Vec<LocalArtifact> = detection
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| a.as_object().cloned())
        .collect();
    if let Some(workspace_dir) = workspace_dir {
        let mut existing_ids: std::collections::HashSet<String> = artifacts
            .iter()
            .map(|a| a_str(a, "artifact_id").unwrap_or("").to_string())
            .collect();
        for artifact in
            deps.items
                .discover_shared_workspace_aibom_artifacts(&harness, home_dir, workspace_dir)
        {
            let aid = a_str(&artifact, "artifact_id").unwrap_or("").to_string();
            if !existing_ids.contains(&aid) {
                existing_ids.insert(aid);
                artifacts.push(artifact);
            }
        }
    }
    artifacts
        .into_iter()
        .filter(|a| a_str(a, "artifact_type") != Some("skill_file"))
        .collect()
}

/// `inventory_snapshot_from_detection(detection, *, generated_at, home_dir, workspace_dir=None, runtime_version=None, cisco_runs=(), include_symlinks=True, follow_unsafe_symlinks=False, trust_attestation_context=None, artifacts=None)`
#[allow(clippy::too_many_arguments)]
pub fn inventory_snapshot_from_detection(
    detection: &CloudInventoryDetection,
    deps: &InventoryDeps<'_>,
    generated_at: &str,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
    runtime_version: Option<&str>,
    cisco_runs: &[CiscoRun],
    include_symlinks: bool,
    follow_unsafe_symlinks: bool,
    trust_attestation_context: Option<&Map<String, Value>>,
    artifacts: Option<&[LocalArtifact]>,
) -> GuardAgentInventorySnapshot {
    let harness = a_str(detection, "harness").unwrap_or("unknown").to_string();
    let artifact_list: Vec<LocalArtifact> = match artifacts {
        Some(list) => list.to_vec(),
        None => cloud_inventory_artifacts_from_detection(detection, deps, home_dir, workspace_dir),
    };
    let mut items: Vec<GuardAgentInventoryItem> = Vec::new();
    for artifact in &artifact_list {
        let item = deps.items._item_from_artifact(
            &harness,
            artifact,
            generated_at,
            home_dir,
            workspace_dir,
            cisco_runs,
            include_symlinks,
            follow_unsafe_symlinks,
            trust_attestation_context,
        );
        items.push(item.clone());
        items.extend(deps.items._mcp_tool_items_from_artifact(
            &harness,
            artifact,
            &item,
            generated_at,
            home_dir,
            workspace_dir,
            cisco_runs,
            trust_attestation_context,
        ));
    }
    // `tuple(dict.fromkeys(str(p) for p in getattr(detection,"config_paths",())))`
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let config_paths: Vec<String> = detection
        .get("config_paths")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    p.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| p.to_string())
                })
                .filter(|s| seen.insert(s.clone()))
                .collect()
        })
        .unwrap_or_default();
    let config_sources: Vec<GuardInventorySource> = config_paths
        .iter()
        .map(|path| {
            let redacted = deps
                .redaction
                .redact_local_path(Path::new(path), Some(home_dir));
            GuardInventorySource {
                source_id: format!(
                    "{}:config:{}",
                    harness,
                    &deps.fingerprint.fingerprint_text(&redacted)[..12]
                ),
                source_type: "config".into(),
                status: "available".into(),
                detail: redacted,
                captured_at: generated_at.to_string(),
                extra: Map::new(),
            }
        })
        .collect();
    let cisco_findings =
        _cisco_inventory_findings(cisco_runs, deps, &items, home_dir, workspace_dir);
    let symlink_findings = if include_symlinks {
        _symlink_findings_from_items(&harness, &items)
    } else {
        Vec::new()
    };
    let mut all_findings = cisco_findings;
    all_findings.extend(symlink_findings);
    let mut sources = config_sources;
    sources.extend(_cisco_inventory_sources(cisco_runs, deps));
    let snapshot_hash = deps.fingerprint._inventory_snapshot_content_hash(
        &harness,
        &items,
        &all_findings,
        &sources,
        runtime_version,
    );
    GuardAgentInventorySnapshot {
        snapshot_id: format!("{}:snapshot:{}", harness, &snapshot_hash[..24]),
        agent_id: format!("{harness}:local"),
        agent_type: deps.agent_type._agent_type(&harness),
        generated_at: generated_at.to_string(),
        runtime_version: runtime_version.unwrap_or("").to_string(),
        items,
        findings: all_findings,
        sources,
        redaction_report: {
            let mut m = Map::new();
            m.insert("rawSecretsIncluded".into(), json!(false));
            m.insert(
                "redactedFields".into(),
                json!(["headers", "env", "url", "paths", "ciscoFindingText"]),
            );
            m
        },
        extra: Map::new(),
    }
}

// ---------------------------------------------------------------------------
// `inventory_contract_scans.py` — defmap order.
// ---------------------------------------------------------------------------

/// `_artifact_id_for_cisco_finding(safe_path, items)`
pub fn _artifact_id_for_cisco_finding(
    safe_path: Option<&str>,
    items: &[GuardAgentInventoryItem],
) -> String {
    let safe_path = match safe_path {
        Some(p) => p,
        None => return "unknown".to_string(),
    };
    for item in items {
        if let Some(config_path) = item.metadata.get("configPath").and_then(Value::as_str) {
            if config_path == safe_path || config_path.ends_with(safe_path) {
                return item.item_id.clone();
            }
        }
    }
    "unknown".to_string()
}

/// `_source_status_for_cisco_status(status)`
pub fn _source_status_for_cisco_status(status: &str) -> &'static str {
    match status {
        "enabled" => "available",
        "failed" | "timed_out" => "failed",
        _ => "missing",
    }
}

/// `_cisco_source(run)`
pub fn _cisco_source(run: &Map<String, Value>) -> Option<InventoryFindingSource> {
    let source = run_str(run, "source").unwrap_or("");
    match source {
        "cisco-mcp-scanner" => Some("cisco-mcp-scanner"),
        "cisco-skill-scanner" => Some("cisco-skill-scanner"),
        _ => None,
    }
}

/// `_inventory_severity(value)`
pub fn _inventory_severity(value: &Value) -> InventorySeverity {
    // `str(getattr(value, "value", value)).strip().lower()` — for `Severity`
    // enum mirrors carry `.value`, else the raw string.
    let raw = value
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
        .unwrap_or("");
    match raw.trim().to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "info",
    }
}

/// `_score_delta_for_severity(severity)`
pub fn _score_delta_for_severity(severity: &str) -> i64 {
    match severity {
        "critical" => -40,
        "high" => -25,
        "medium" => -12,
        "low" => -5,
        _ => 0,
    }
}

/// `_cisco_inventory_findings(cisco_runs, *, items, home_dir, workspace_dir)`
pub fn _cisco_inventory_findings(
    cisco_runs: &[CiscoRun],
    deps: &InventoryDeps<'_>,
    items: &[GuardAgentInventoryItem],
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> Vec<GuardAgentInventoryFinding> {
    let mut findings: Vec<GuardAgentInventoryFinding> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for run in cisco_runs {
        let source = match _cisco_source(run) {
            Some(s) => s,
            None => continue,
        };
        let run_status = run_str(run, "status").unwrap_or("unknown").to_string();
        let run_message = deps.redaction._safe_finding_text(
            run_str(run, "message").unwrap_or(""),
            home_dir,
            workspace_dir,
        );
        let duration_ms = run.get("duration_ms").cloned();
        for raw_finding in run_findings(run) {
            let raw_finding = match raw_finding.as_object() {
                Some(f) => f,
                None => continue,
            };
            let rule_id = run_str(raw_finding, "rule_id")
                .filter(|s| !s.is_empty())
                .unwrap_or("cisco-finding")
                .to_string();
            let title = deps.redaction._safe_finding_text(
                run_str(raw_finding, "title")
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Cisco scanner finding"),
                home_dir,
                workspace_dir,
            );
            let file_path = run_str(raw_finding, "file_path");
            let safe_path = match file_path {
                Some(p) if !p.is_empty() => Some(deps.redaction._redact_known_path(
                    p,
                    home_dir,
                    workspace_dir,
                )),
                _ => None,
            };
            let line_number = run
                .get("line_number")
                .and_then(Value::as_i64)
                .or_else(|| raw_finding.get("line_number").and_then(Value::as_i64));
            let severity = _inventory_severity(raw_finding.get("severity").unwrap_or(&Value::Null));
            let artifact_id = _artifact_id_for_cisco_finding(safe_path.as_deref(), items);
            let finding_id = format!(
                "{}:{}:{}:{}",
                source,
                artifact_id,
                rule_id,
                line_number
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "0".into())
            );
            if !seen.insert(finding_id.clone()) {
                continue;
            }
            let mut evidence = Map::new();
            evidence.insert("status".into(), json!(run_status));
            evidence.insert("message".into(), json!(run_message));
            if let Some(d) = duration_ms.clone() {
                evidence.insert("durationMs".into(), d);
            }
            if let Some(p) = safe_path.clone() {
                evidence.insert("filePath".into(), json!(p));
            }
            if let Some(ln) = line_number {
                evidence.insert("lineNumber".into(), json!(ln));
            }
            findings.push(GuardAgentInventoryFinding {
                finding_id,
                source: source.to_string(),
                severity: severity.to_string(),
                confidence: "high".into(),
                title,
                artifact_id,
                check_id: format!("aibom.{source}.{rule_id}"),
                summary: run_message.clone(),
                evidence,
                extra: Map::new(),
            });
        }
    }
    findings
}

/// `_cisco_inventory_sources(cisco_runs)`
pub fn _cisco_inventory_sources(
    cisco_runs: &[CiscoRun],
    deps: &InventoryDeps<'_>,
) -> Vec<GuardInventorySource> {
    let mut sources = Vec::new();
    for run in cisco_runs {
        let source = match _cisco_source(run) {
            Some(s) => s,
            None => continue,
        };
        let run_status = run_str(run, "status").unwrap_or("unknown").to_string();
        let detail = deps.redaction._safe_source_detail(run);
        sources.push(GuardInventorySource {
            source_id: format!("{source}:source:{run_status}"),
            source_type: source.to_string(),
            status: _source_status_for_cisco_status(&run_status).to_string(),
            detail,
            captured_at: run_str(run, "captured_at").unwrap_or("").to_string(),
            extra: Map::new(),
        });
    }
    sources
}

/// `_symlink_findings_from_items(harness, items)`
pub fn _symlink_findings_from_items(
    harness: &str,
    items: &[GuardAgentInventoryItem],
) -> Vec<GuardAgentInventoryFinding> {
    let mut findings = Vec::new();
    for item in items {
        let source_of_truth = item.metadata.get("sourceOfTruth");
        let source_of_truth = match source_of_truth.and_then(Value::as_object) {
            Some(s) => s,
            None => continue,
        };
        let validation_state = source_of_truth
            .get("validationState")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let severity = if validation_state == "loop" || validation_state == "escape_blocked" {
            "high"
        } else {
            "medium"
        };
        let mut evidence = Map::new();
        evidence.insert("validationState".into(), json!(validation_state));
        evidence.insert(
            "sourceFingerprint".into(),
            source_of_truth
                .get("sourceFingerprint")
                .cloned()
                .unwrap_or(Value::Null),
        );
        evidence.insert(
            "pathClass".into(),
            source_of_truth
                .get("pathClass")
                .cloned()
                .unwrap_or(Value::Null),
        );
        findings.push(GuardAgentInventoryFinding {
            finding_id: format!("{}:symlink:{}:{}", harness, item.item_id, validation_state),
            source: "hol-detector".into(),
            severity: severity.into(),
            confidence: "high".into(),
            title: format!("Symlink source {}", validation_state.replace('_', " ")),
            artifact_id: item.item_id.clone(),
            check_id: format!("aibom.symlink.{validation_state}"),
            summary: format!(
                "Inventory item references a symlink source in state {validation_state}."
            ),
            evidence,
            extra: Map::new(),
        });
    }
    findings
}
