//! `InventoryScanFindings` — resident op turning a scanner run and an
//! inventory's recorded symlink evidence into findings and sources.
//!
//! Three readings decide what a scan reports, and each one is a protection
//! decision. A severity that normalizes the wrong way moves the inventory's
//! score by the wrong amount. A scanner that failed but reports as merely
//! missing reads as a clean scan rather than an absent one. A symlink that
//! escaped its root, or looped, and reports nothing at all hides the evidence
//! the detector already gathered. `guard_command::inventory_contract` owns the
//! grammar for all three, so the caller asks rather than keeping a second copy
//! of the rules that could answer differently.
//!
//! The findings also cross a privacy boundary. Scanner titles, descriptions,
//! messages and file paths quote the operator's own filesystem, and the same
//! request that classifies them redacts them, so no caller can publish the raw
//! text by forgetting to redact first.
//!
//! The whole scan rides in one request: a snapshot covers every run and every
//! item a detection found, and asking per finding would put the resident on an
//! inventory's critical path a few hundred times over.

use std::path::{Path, PathBuf};

use guard_command::inventory_contract::{
    CiscoRun, GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource,
    InventoryDeps, LocalArtifact, _cisco_inventory_findings, _cisco_inventory_sources,
    _symlink_findings_from_items,
};
use guard_command::inventory_path_redaction::NativeInventoryRedaction;
use guard_contracts::{
    InventoryScanFindingsItemV1, InventoryScanFindingsRequestV1, InventoryScanFindingsResultV1,
    INVENTORY_SCAN_FINDINGS_MAX_BYTES, INVENTORY_SCAN_FINDINGS_MAX_ITEMS,
    INVENTORY_SCAN_FINDINGS_MAX_RUNS, INVENTORY_SCAN_FINDINGS_REQUEST_SCHEMA,
    INVENTORY_SCAN_FINDINGS_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_inventory_scan_findings_request(
    request: &InventoryScanFindingsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, INVENTORY_SCAN_FINDINGS_MAX_BYTES)
        .map_err(|_| "native_inventory_scan_findings_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => match bounded_payload(request) {
            Ok(payload) => ("ok", "ok", Some(payload)),
            Err(code) => ("error", code, None),
        },
    };
    crate::encode_response(&InventoryScanFindingsResultV1 {
        schema: INVENTORY_SCAN_FINDINGS_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// Largest payload one reply carries.
///
/// The resident frames at most `MAX_NATIVE_RESPONSE_BYTES`, and the reply wraps
/// this payload in its schema, request id and digest, so the payload is held a
/// frame's slack below that ceiling.
const MAX_PAYLOAD_BYTES: usize = crate::MAX_NATIVE_RESPONSE_BYTES - 64 * 1024;

/// The scan's answer, or the code to refuse it with when it will not fit a
/// reply.
///
/// The run and item caps bound what a request may carry, not what an answer
/// grows to: a run's status, message and duration ride in the evidence of every
/// finding that run produced, so a few hundred small findings in a request can
/// describe far more bytes coming back than they took going out. Measuring the
/// payload here is what lets the caller hear which scan was too large to answer,
/// rather than the frame boundary reporting an answer that cannot be delivered
/// as a runtime that stopped responding.
fn bounded_payload(request: &InventoryScanFindingsRequestV1) -> Result<Value, &'static str> {
    let payload = evaluate_request(request);
    match serde_json::to_vec(&payload) {
        Ok(encoded) if encoded.len() > MAX_PAYLOAD_BYTES => {
            Err("native_inventory_scan_findings_reply_too_large")
        }
        // A payload that will not serialize at all is not this op's refusal to
        // make: `encode_response` names an encoding failure for what it is.
        _ => Ok(payload),
    }
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &InventoryScanFindingsRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != INVENTORY_SCAN_FINDINGS_REQUEST_SCHEMA {
        return Some("native_inventory_scan_findings_schema_mismatch");
    }
    if request.cisco_runs.len() > INVENTORY_SCAN_FINDINGS_MAX_RUNS {
        return Some("native_inventory_scan_findings_too_many_runs");
    }
    if request.items.len() > INVENTORY_SCAN_FINDINGS_MAX_ITEMS {
        return Some("native_inventory_scan_findings_too_many_items");
    }
    None
}

/// The scanner findings followed by the symlink findings, and the scanner
/// sources, each in the order the request listed its runs and items.
pub(crate) fn evaluate_request(request: &InventoryScanFindingsRequestV1) -> Value {
    let cwd = PathBuf::from(&request.cwd);
    let redaction = NativeInventoryRedaction { cwd: &cwd };
    let deps = InventoryDeps {
        redaction: &redaction,
        fingerprint: &UnusedSeam,
        agent_type: &UnusedSeam,
        items: &UnusedSeam,
    };
    let home_dir = PathBuf::from(&request.home_dir);
    let workspace_dir = request.workspace_dir.as_deref().map(Path::new);
    let items: Vec<GuardAgentInventoryItem> = request.items.iter().map(project_item).collect();
    let mut findings =
        _cisco_inventory_findings(&request.cisco_runs, &deps, &items, &home_dir, workspace_dir);
    if request.include_symlinks {
        findings.extend(_symlink_findings_from_items(&request.harness, &items));
    }
    let sources = _cisco_inventory_sources(&request.cisco_runs, &deps);
    json!({
        "findings": findings.iter().map(finding_json).collect::<Vec<Value>>(),
        "sources": sources.iter().map(source_json).collect::<Vec<Value>>(),
    })
}

/// The item fields the finding grammar reads.
///
/// `configPath` associates a scanner finding with the artifact it belongs to
/// and `sourceOfTruth` carries the symlink evidence; nothing else about an item
/// is read, so nothing else is carried.
fn project_item(entry: &InventoryScanFindingsItemV1) -> GuardAgentInventoryItem {
    GuardAgentInventoryItem {
        item_id: entry.item_id.clone(),
        metadata: entry.metadata.clone(),
        ..GuardAgentInventoryItem::default()
    }
}

/// One finding as the caller's dataclass keyword arguments.
fn finding_json(finding: &GuardAgentInventoryFinding) -> Value {
    json!({
        "finding_id": finding.finding_id,
        "source": finding.source,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "title": finding.title,
        "artifact_id": finding.artifact_id,
        "check_id": finding.check_id,
        "summary": finding.summary,
        "evidence": finding.evidence,
    })
}

/// One source as the caller's dataclass keyword arguments.
fn source_json(source: &GuardInventorySource) -> Value {
    json!({
        "source_id": source.source_id,
        "source_type": source.source_type,
        "status": source.status,
        "captured_at": source.captured_at,
        "detail": source.detail,
    })
}

/// The seams [`InventoryDeps`] bundles that this request never reaches.
///
/// The scan grammar reads only the redaction seam. Rather than build a
/// fingerprint, agent-type and item-projection implementation this op has no
/// input for, the unused seams panic if a future change starts calling them,
/// so the gap shows up as a failing test rather than as a quietly invented
/// answer.
struct UnusedSeam;

impl guard_command::inventory_contract::FingerprintApi for UnusedSeam {
    fn fingerprint_text(&self, _value: &str) -> String {
        unreachable!("inventory-scan-findings does not fingerprint through the seam")
    }

    fn fingerprint_mapping(&self, _value: &Value) -> String {
        unreachable!("inventory-scan-findings does not fingerprint through the seam")
    }

    fn inventory_item_id(
        &self,
        _agent_type: &str,
        _item_kind: &str,
        _display_name: &str,
        _semantic_text: &str,
    ) -> String {
        unreachable!("inventory-scan-findings does not mint item ids")
    }

    fn _inventory_snapshot_content_hash(
        &self,
        _agent_type: &str,
        _items: &[GuardAgentInventoryItem],
        _findings: &[GuardAgentInventoryFinding],
        _sources: &[GuardInventorySource],
        _runtime_version: Option<&str>,
    ) -> String {
        unreachable!("inventory-scan-findings does not hash snapshots")
    }
}

impl guard_command::inventory_contract::AgentTypeApi for UnusedSeam {
    fn _agent_type(&self, _agent_id: &str) -> String {
        unreachable!("inventory-scan-findings does not resolve agent types")
    }
}

impl guard_command::inventory_contract::ItemProjectionApi for UnusedSeam {
    #[allow(clippy::too_many_arguments)]
    fn _item_from_artifact(
        &self,
        _harness: &str,
        _artifact: &LocalArtifact,
        _generated_at: &str,
        _home_dir: &Path,
        _workspace_dir: Option<&Path>,
        _cisco_runs: &[CiscoRun],
        _include_symlinks: bool,
        _follow_unsafe_symlinks: bool,
        _trust_attestation_context: Option<&Map<String, Value>>,
    ) -> GuardAgentInventoryItem {
        unreachable!("inventory-scan-findings does not project artifacts")
    }

    #[allow(clippy::too_many_arguments)]
    fn _mcp_tool_items_from_artifact(
        &self,
        _harness: &str,
        _artifact: &LocalArtifact,
        _item: &GuardAgentInventoryItem,
        _generated_at: &str,
        _home_dir: &Path,
        _workspace_dir: Option<&Path>,
        _cisco_runs: &[CiscoRun],
        _trust_attestation_context: Option<&Map<String, Value>>,
    ) -> Vec<GuardAgentInventoryItem> {
        unreachable!("inventory-scan-findings does not project artifacts")
    }

    fn discover_shared_workspace_aibom_artifacts(
        &self,
        _harness: &str,
        _home_dir: &Path,
        _workspace_dir: &Path,
    ) -> Vec<LocalArtifact> {
        unreachable!("inventory-scan-findings does not discover artifacts")
    }
}

#[cfg(test)]
#[path = "inventory_scan_findings_op_tests.rs"]
mod tests;
