//! `AibomReportSummaries` — resident op that counts an AIBOM report's layers,
//! trust coverage and drift.
//!
//! Python held a second copy of this grammar: which item kinds land in which
//! layer, when a source link counts and when a source of truth counts in its
//! place, which kinds are eligible for trust coverage and what makes a score
//! low, which drift states are totalled and what makes an item high risk. All
//! of it already lived in `aibom_reporting::summarize_aibom_layers`, so the
//! caller now sends the rows and reads the three summaries it answers with.

use guard_command::aibom_reporting::{
    summarize_aibom_layers, GuardAgentInventorySnapshot, InventoryDrift, InventoryItem,
};
use guard_contracts::{
    AibomReportSummariesRequestV1, AibomReportSummariesResultV1, AibomSummarySnapshotV1,
    AIBOM_REPORT_SUMMARIES_MAX_REQUEST_BYTES, AIBOM_REPORT_SUMMARIES_MAX_ROWS,
    AIBOM_REPORT_SUMMARIES_REQUEST_SCHEMA, AIBOM_REPORT_SUMMARIES_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

use crate::package_authority_op::request_digest_with_limit;

fn invalid() -> String {
    "native_aibom_report_summaries_invalid".to_owned()
}

/// Rebuild the snapshot the grammar reads from the projection on the wire.
///
/// The findings and the sources only ever reach the grammar through their
/// length, so the counts stand in for rows the caller never sent.
/// The measured rows a request asks the resident to stand in for, summed over
/// every snapshot. `None` when the sum overflows.
fn measured_rows(snapshots: &[AibomSummarySnapshotV1]) -> Option<u64> {
    snapshots.iter().try_fold(0u64, |total, wire| {
        total
            .checked_add(wire.finding_count)?
            .checked_add(wire.source_count)
    })
}

fn snapshot(wire: &AibomSummarySnapshotV1) -> GuardAgentInventorySnapshot {
    let items = wire
        .items
        .iter()
        .map(|item| {
            let mut metadata = Map::new();
            metadata.insert("trustResolution".to_owned(), item.trust_resolution.clone());
            metadata.insert("sourceLinks".to_owned(), item.source_links.clone());
            metadata.insert("sourceOfTruth".to_owned(), item.source_of_truth.clone());
            InventoryItem {
                item_kind: item.item_kind.clone(),
                risk_level: item.risk_level.clone(),
                drift_state: item.drift_state.clone(),
                metadata,
                ..InventoryItem::default()
            }
        })
        .collect();
    GuardAgentInventorySnapshot {
        items,
        findings: vec![Value::Null; wire.finding_count as usize],
        sources: vec![Value::Null; wire.source_count as usize],
        drift: wire
            .drift_states
            .iter()
            .map(|state| InventoryDrift {
                state: state.clone(),
            })
            .collect(),
        ..GuardAgentInventorySnapshot::default()
    }
}

pub(crate) fn evaluate_aibom_report_summaries(
    request: &AibomReportSummariesRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, AIBOM_REPORT_SUMMARIES_MAX_REQUEST_BYTES)?;
    if request.schema != AIBOM_REPORT_SUMMARIES_REQUEST_SCHEMA {
        return Err("native_aibom_report_summaries_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() {
        return Err(invalid());
    }
    // Checked before any placeholder row is built: many compact snapshots
    // must not add up to more rows than one request may stand in for.
    if measured_rows(&request.snapshots).is_none_or(|rows| rows > AIBOM_REPORT_SUMMARIES_MAX_ROWS) {
        return Err(invalid());
    }
    let snapshots: Vec<_> = request.snapshots.iter().map(snapshot).collect();
    let (layer_summary, trust, drift) = summarize_aibom_layers(&snapshots, &request.generated_at);
    let mut payload = Map::new();
    payload.insert("layer_summary".to_owned(), Value::Object(layer_summary));
    payload.insert("trust".to_owned(), Value::Object(trust));
    payload.insert("drift".to_owned(), Value::Object(drift));
    crate::encode_response(&AibomReportSummariesResultV1 {
        schema: AIBOM_REPORT_SUMMARIES_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(Value::Object(payload)),
    })
}

#[cfg(test)]
#[path = "aibom_report_summaries_op_tests.rs"]
mod tests;
