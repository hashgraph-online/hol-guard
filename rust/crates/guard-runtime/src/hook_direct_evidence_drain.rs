//! Native drain and acknowledgment of direct hook evidence.

use serde::Deserialize;
use serde_json::{json, Value};

use super::{record, DirectEvidenceQueue, HookDirectEvidenceDrainRequestV1, Paged, RECEIPT_VALID};
use crate::mcp_relay_receipt;

const DEFAULT_DRAIN_RECORDS: usize = 256;
const UNHANDLED: &str = "direct_hook_evidence_unhandled";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDirectEvidenceCommitRequestV1 {
    pub(crate) guard_home: String,
}

pub(crate) fn drain(
    request: &HookDirectEvidenceDrainRequestV1,
    queue: &DirectEvidenceQueue,
    writer_source: Option<&str>,
) -> Result<Vec<u8>, String> {
    let max_records = request
        .max_records
        .unwrap_or(DEFAULT_DRAIN_RECORDS)
        .clamp(1, DEFAULT_DRAIN_RECORDS);
    let recording = queue
        .recording
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let peeked = queue.acknowledge_and_peek(
        request.ack_through,
        request.ack_epoch.as_deref(),
        max_records,
    );
    let home = &request.guard_home;
    mcp_relay_receipt::write_detached(home, peeked.settled, queue.unwritten());
    let mut paged = peeked.records;
    let store_fatal = record_page(queue, home, writer_source, &mut paged)?;
    drop(recording);
    let sequences: Vec<u64> = paged.iter().map(|paged| paged.seq).collect();
    let records: Vec<Value> = paged.into_iter().map(|paged| paged.record).collect();
    encode(
        json!({
            "schema": "guard-hook-direct-evidence.v1",
            "epoch": queue.epoch,
            "records": records,
            "sequences": sequences,
            "remaining": peeked.remaining,
            "through": peeked.through,
            "counters": queue.counters.snapshot(),
        }),
        store_fatal,
    )
}

pub(crate) fn commit_page(
    request: &HookDirectEvidenceCommitRequestV1,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    commit_queued_page(
        &request.guard_home,
        store.direct_evidence(),
        store.direct_lane_writer_source().as_deref(),
    )
}

pub(crate) fn commit_queued_page(
    home: &str,
    queue: &DirectEvidenceQueue,
    writer_source: Option<&str>,
) -> Result<Vec<u8>, String> {
    let recording = queue
        .recording
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let peeked = queue.acknowledge_and_peek(None, None, DEFAULT_DRAIN_RECORDS);
    let mut paged = peeked.records;
    let paged_count = paged.len();
    let store_fatal = record_page(queue, home, writer_source, &mut paged)?;
    // Without a configured writer, record_page only validates the receipt.
    // Keep any such record that still needs work on the queue.
    if has_unfinished_records(&paged, home) {
        return Err(UNHANDLED.to_owned());
    }
    let settled = match peeked.through {
        Some(through) => queue
            .state
            .lock()
            .map_err(|_| UNHANDLED.to_owned())?
            .acknowledge(through),
        None => Vec::new(),
    };
    let record_count = paged_count + settled.len();
    // Plain relay receipts retain their existing resident writer and retry
    // queue. The client only receives aggregate diagnostics.
    mcp_relay_receipt::write_detached(home, settled, queue.unwritten());
    drop(recording);
    encode(
        json!({
            "schema": "guard-hook-direct-evidence-commit.v1",
            "epoch": queue.epoch,
            "record_count": record_count,
            "remaining": peeked.remaining,
            "counters": queue.counters.snapshot(),
        }),
        store_fatal,
    )
}

fn record_page(
    queue: &DirectEvidenceQueue,
    home: &str,
    writer_source: Option<&str>,
    paged: &mut Vec<Paged>,
) -> Result<Option<Value>, String> {
    for item in paged.iter_mut() {
        if let Some(receipt) = item
            .record
            .get("receipt")
            .filter(|receipt| receipt.is_object())
        {
            let valid = crate::edge::standalone_receipt(receipt, &Value::Null);
            item.record[RECEIPT_VALID] = Value::Bool(valid);
        }
    }
    let Some(source) = writer_source.filter(|_| !home.is_empty()) else {
        return Ok(None);
    };
    let fatal = record::leftovers(queue, home, source, paged);
    record::drop_settled(paged, home);
    // A plain receipt that the detached writer returned stays queued until
    // its retry succeeds.
    let plain: Vec<_> = paged
        .iter()
        .filter(|item| mcp_relay_receipt::is_plain(&item.record))
        .map(|item| item.record.clone())
        .collect();
    if !plain.is_empty() {
        let unwritten = mcp_relay_receipt::write(home, plain);
        paged.retain(|item| {
            !mcp_relay_receipt::is_plain(&item.record) || unwritten.contains(&item.record)
        });
    }
    if has_unfinished_records(paged, home) {
        return Err(UNHANDLED.to_owned());
    }
    Ok(fatal)
}

fn has_unfinished_records(paged: &[Paged], home: &str) -> bool {
    paged
        .iter()
        .any(|item| mcp_relay_receipt::is_plain(&item.record) || record::needs_work(item, home))
}

fn encode(mut page: Value, store_fatal: Option<Value>) -> Result<Vec<u8>, String> {
    if let Some(fatal) = store_fatal.filter(|fatal| !fatal.is_null()) {
        page["store_fatal"] = fatal;
    }
    serde_json::to_vec(&page).map_err(|_| "direct_hook_evidence_encoding_failed".to_owned())
}
