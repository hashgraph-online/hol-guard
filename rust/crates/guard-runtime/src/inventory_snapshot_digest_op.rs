//! `InventorySnapshotDigest` — resident op computing an inventory snapshot's
//! content identity.
//!
//! The digest decides whether a snapshot counts as changed, so the rules that
//! make it repeatable — which observation fields are dropped, how nested lists
//! are ordered, how items, findings and sources are sorted, and the exact JSON
//! the hash is taken over — are one grammar in `inventory_fingerprints`. This
//! op is the way a caller assembling a snapshot reaches it.
//!
//! The request carries the snapshot's rows as the caller holds them. Fields
//! the mirror structs name are read directly; the rest ride in `extra`, where
//! a missing key means the dataclass default rather than an absent value.

use guard_command::inventory_contract::{
    GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource,
};
use guard_command::inventory_fingerprints::inventory_snapshot_content_hash;
use guard_contracts::{
    InventorySnapshotDigestRequestV1, InventorySnapshotDigestResultV1,
    INVENTORY_SNAPSHOT_DIGEST_MAX_BYTES, INVENTORY_SNAPSHOT_DIGEST_REQUEST_SCHEMA,
    INVENTORY_SNAPSHOT_DIGEST_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_inventory_snapshot_digest_request(
    request: &InventorySnapshotDigestRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, INVENTORY_SNAPSHOT_DIGEST_MAX_BYTES)
        .map_err(|_| "native_inventory_snapshot_digest_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(json!({ "digest": digest_for(request) }))),
    };
    crate::encode_response(&InventorySnapshotDigestResultV1 {
        schema: INVENTORY_SNAPSHOT_DIGEST_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &InventorySnapshotDigestRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != INVENTORY_SNAPSHOT_DIGEST_REQUEST_SCHEMA {
        return Some("native_inventory_snapshot_digest_schema_mismatch");
    }
    // Every row is an object of dataclass fields. A row of any other shape
    // would read as a row of defaults, which is a digest over something the
    // caller did not send.
    let rows = request
        .items
        .iter()
        .chain(request.findings.iter())
        .chain(request.sources.iter());
    if rows.into_iter().any(|row| !row.is_object()) {
        return Some("native_inventory_snapshot_digest_invalid_row");
    }
    None
}

fn digest_for(request: &InventorySnapshotDigestRequestV1) -> String {
    let items: Vec<GuardAgentInventoryItem> = request.items.iter().map(item_from).collect();
    let findings: Vec<GuardAgentInventoryFinding> =
        request.findings.iter().map(finding_from).collect();
    let sources: Vec<GuardInventorySource> = request.sources.iter().map(source_from).collect();
    inventory_snapshot_content_hash(
        &request.agent_type,
        &items,
        &findings,
        &sources,
        request.runtime_version.as_deref(),
    )
}

fn item_from(row: &Value) -> GuardAgentInventoryItem {
    GuardAgentInventoryItem {
        item_id: text(row, "item_id"),
        item_kind: text(row, "item_kind"),
        display_name: text(row, "display_name"),
        metadata: object(row, "metadata"),
        capability_categories: string_list(row, "capability_categories"),
        content_hash: text(row, "content_hash"),
        drift_state: text(row, "drift_state"),
        extra: extra(
            row,
            &[
                "risk_level",
                "scanner_sources",
                "security_score",
                "source_fingerprint",
            ],
        ),
    }
}

fn finding_from(row: &Value) -> GuardAgentInventoryFinding {
    GuardAgentInventoryFinding {
        finding_id: text(row, "finding_id"),
        source: text(row, "source"),
        severity: text(row, "severity"),
        confidence: text(row, "confidence"),
        title: text(row, "title"),
        artifact_id: text(row, "artifact_id"),
        check_id: text(row, "check_id"),
        summary: optional_text(row, "summary"),
        evidence: object(row, "evidence"),
        extra: Map::new(),
    }
}

fn source_from(row: &Value) -> GuardInventorySource {
    GuardInventorySource {
        source_id: text(row, "source_id"),
        source_type: text(row, "source_type"),
        status: text(row, "status"),
        detail: optional_text(row, "detail"),
        captured_at: optional_text(row, "captured_at"),
        extra: Map::new(),
    }
}

fn text(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `None` and an absent key are the dataclass default; `""` stays `""`, and
/// the digest shows the difference.
fn optional_text(row: &Value, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn object(row: &Value, key: &str) -> Map<String, Value> {
    row.get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn string_list(row: &Value, key: &str) -> Vec<String> {
    row.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The named fields the mirror struct does not carry, kept only when the row
/// actually sent them.
fn extra(row: &Value, keys: &[&str]) -> Map<String, Value> {
    let mut carried = Map::new();
    for key in keys {
        if let Some(value) = row.get(*key) {
            carried.insert((*key).to_owned(), value.clone());
        }
    }
    carried
}

#[cfg(test)]
#[path = "inventory_snapshot_digest_op_tests.rs"]
mod tests;
