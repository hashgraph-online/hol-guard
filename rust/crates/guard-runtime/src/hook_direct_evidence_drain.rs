//! Native drain and acknowledgment of direct hook evidence.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use super::{record, DirectEvidenceQueue, HookDirectEvidenceDrainRequestV1, Paged, RECEIPT_VALID};
use crate::mcp_relay_receipt;

const DEFAULT_DRAIN_RECORDS: usize = 256;
const PAGES_PER_WAKE: usize = 8;
const MAX_BATCH_MS: u64 = 2_000;
const UNHANDLED: &str = "direct_hook_evidence_unhandled";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDirectEvidenceCommitRequestV1 {
    pub(crate) guard_home: String,
    batch: Batch,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    budget_ms: u64,
    shutdown: bool,
}

struct CommittedPage {
    record_count: usize,
    remaining: usize,
    store_fatal: Option<Value>,
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
    let queue = store.direct_evidence();
    let batch = &request.batch;
    if !(1..=MAX_BATCH_MS).contains(&batch.budget_ms) {
        return Err("direct_hook_evidence_batch_budget_invalid".to_owned());
    }
    let deadline = Instant::now() + Duration::from_millis(batch.budget_ms);
    commit_batch(queue, batch.shutdown, deadline, || {
        commit_queued(
            &request.guard_home,
            queue,
            store.direct_lane_writer_source().as_deref(),
        )
    })
}

fn commit_batch(
    queue: &DirectEvidenceQueue,
    shutdown: bool,
    deadline: Instant,
    mut next: impl FnMut() -> Result<CommittedPage, String>,
) -> Result<Vec<u8>, String> {
    let mut pages = 0;
    let mut record_count = 0usize;
    let mut remaining = 0;
    let mut failed = false;
    let mut failure = None;
    let mut store_fatal = None;
    while Instant::now() < deadline && (shutdown || pages < PAGES_PER_WAKE) {
        match next() {
            Ok(page) => {
                pages += 1;
                record_count = record_count.saturating_add(page.record_count);
                remaining = page.remaining;
                store_fatal = page.store_fatal.filter(|fatal| !fatal.is_null());
                if remaining == 0 || store_fatal.is_some() {
                    break;
                }
            }
            Err(error) if pages == 0 => {
                return encode(
                    json!({
                        "schema": "guard-hook-direct-evidence-batch.v1",
                        "epoch": queue.epoch,
                        "pages": 0,
                        "record_count": 0,
                        "more": false,
                        "failed": true,
                        "failure": error,
                        "counters": queue.counters.snapshot(),
                    }),
                    store_fatal,
                );
            }
            Err(error) => {
                failed = true;
                failure = Some(error);
                break;
            }
        }
    }
    encode(
        json!({
            "schema": "guard-hook-direct-evidence-batch.v1",
            "epoch": queue.epoch,
            "pages": pages,
            "record_count": record_count,
            "more": pages > 0 && remaining > 0 && !failed,
            "failed": failed,
            "failure": failure,
            "counters": queue.counters.snapshot(),
        }),
        store_fatal,
    )
}

#[cfg(test)]
pub(crate) fn commit_test_batch(
    home: &str,
    queue: &DirectEvidenceQueue,
    writer_source: Option<&str>,
) -> Result<Vec<u8>, String> {
    commit_batch(
        queue,
        false,
        Instant::now() + Duration::from_millis(MAX_BATCH_MS),
        || commit_queued(home, queue, writer_source),
    )
}

fn commit_queued(
    home: &str,
    queue: &DirectEvidenceQueue,
    writer_source: Option<&str>,
) -> Result<CommittedPage, String> {
    let recording = queue
        .recording
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let peeked = queue.acknowledge_and_peek_for_commit(DEFAULT_DRAIN_RECORDS);
    let mut paged = peeked.records;
    let paged_count = paged.len();
    let store_fatal = record_page(queue, home, writer_source, &mut paged)?;
    // Without a configured writer, record_page only validates the receipt.
    // Keep any such record that still needs work on the queue.
    if has_unfinished_records(&paged, home) {
        return Err(UNHANDLED.to_owned());
    }
    // The commit page included resident-owned records so `record_page` could
    // write them. Acknowledging the cursor is therefore sufficient. Do not
    // send those records through the detached writer a second time.
    if let Some(through) = peeked.through {
        let _ = queue
            .state
            .lock()
            .map_err(|_| UNHANDLED.to_owned())?
            .acknowledge(through);
    }
    let settled = Vec::new();
    let record_count = paged_count + settled.len();
    // The client only receives aggregate diagnostics after the commit has
    // acknowledged the page.
    mcp_relay_receipt::write_detached(home, settled, queue.unwritten());
    drop(recording);
    Ok(CommittedPage {
        record_count,
        remaining: peeked.remaining,
        store_fatal,
    })
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
        // Relayed MCP records own their Rust receipt and review-row writer.
        // They can be committed without the daemon's command-activity source,
        // which is absent in short-lived relay-only workers.
        let plain: Vec<_> = paged
            .iter()
            .filter(|item| mcp_relay_receipt::is_plain(&item.record))
            .map(|item| (item.seq, item.record.clone()))
            .collect();
        if !plain.is_empty() {
            let unwritten = mcp_relay_receipt::write_indexed(home, plain);
            if !unwritten.is_empty() {
                return Err(format!("mcp_relay_receipt_unwritten:{}", unwritten.len()));
            }
            keep_handed_back(queue, paged, &unwritten);
        } else if paged
            .iter()
            .any(|item| item.record.get("kind").and_then(Value::as_str) == Some("mcp_tool_call"))
        {
            return Err("mcp_relay_record_not_plain".to_owned());
        }
        return Ok(None);
    };
    let fatal = record::leftovers(queue, home, source, paged);
    record::drop_settled(paged, home);
    // A plain receipt that the detached writer returned stays queued until
    // its retry succeeds.
    let plain: Vec<_> = paged
        .iter()
        .filter(|item| mcp_relay_receipt::is_plain(&item.record))
        .map(|item| (item.seq, item.record.clone()))
        .collect();
    if !plain.is_empty() {
        let unwritten = mcp_relay_receipt::write_indexed(home, plain);
        if !unwritten.is_empty() {
            return Err(format!("mcp_relay_receipt_unwritten:{}", unwritten.len()));
        }
        keep_handed_back(queue, paged, &unwritten);
    } else if paged
        .iter()
        .any(|item| item.record.get("kind").and_then(Value::as_str) == Some("mcp_tool_call"))
    {
        return Err("mcp_relay_record_not_plain".to_owned());
    }
    if has_unfinished_records(paged, home) {
        return Err(UNHANDLED.to_owned());
    }
    Ok(fatal)
}

/// Keep the plain records the writer handed back, each in the form it came
/// back in. A remembered record whose allow was saved returns without its
/// flag, and its queued copy loses the flag too, so a later drain retries
/// only the receipt and never saves the allow a second time. A record the
/// writer finished leaves the queue now: a later record on the same page may
/// still fail the page, and the retry must not save its allow or write its
/// receipt again.
fn keep_handed_back(
    queue: &DirectEvidenceQueue,
    paged: &mut Vec<Paged>,
    unwritten: &[(u64, Value)],
) {
    let mut state = queue.state.lock().ok();
    paged.retain_mut(|item| {
        if !mcp_relay_receipt::is_plain(&item.record) {
            return true;
        }
        let Some(record) =
            mcp_relay_receipt::remember::handed_back_with_sequence(item.seq, unwritten)
        else {
            if let Some(state) = state.as_mut() {
                state.forget(item.seq);
            }
            return false;
        };
        if record != item.record {
            if let Some(state) = state.as_mut() {
                state.replace(item.seq, record.clone());
            }
            item.record = record;
        }
        true
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_queued_record_handed_back_without_its_flag_loses_the_flag_in_the_queue() {
        let queue = DirectEvidenceQueue::default();
        let mut queued =
            crate::mcp_relay_receipt::tests::record("forward", "inline-approved", "allow");
        queued["remember"] = json!(true);
        queue.unwritten().requeue(vec![queued.clone()]);
        let mut forward = queued.clone();
        forward.as_object_mut().unwrap().remove("remember");
        let mut paged = queue
            .acknowledge_and_peek(None, None, DEFAULT_DRAIN_RECORDS)
            .records;
        let sequence = paged[0].seq;
        keep_handed_back(&queue, &mut paged, &[(sequence, forward.clone())]);
        assert_eq!(paged.len(), 1);
        assert_eq!(paged[0].record, forward);
        let again = queue
            .acknowledge_and_peek(None, None, DEFAULT_DRAIN_RECORDS)
            .records;
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].record, forward);

        let mut written = again;
        keep_handed_back(&queue, &mut written, &[]);
        assert!(written.is_empty());
        // The finished record left the queue, so no later page writes it.
        let after = queue
            .acknowledge_and_peek(None, None, DEFAULT_DRAIN_RECORDS)
            .records;
        assert!(after.is_empty());
    }

    /// One page holds two remembered records: the first is written in full,
    /// the second comes back stripped. The page fails on the second, and the
    /// retry sees only the second, without its flag.
    #[test]
    fn a_failed_page_retries_only_what_the_writer_handed_back() {
        let queue = DirectEvidenceQueue::default();
        let remembered = |tool: &str| {
            let mut record =
                crate::mcp_relay_receipt::tests::record("forward", "inline-approved", "allow");
            record["tool_name"] = json!(tool);
            record["params"]["name"] = json!(tool);
            record["remember"] = json!(true);
            record
        };
        let (first, second) = (remembered("first"), remembered("second"));
        queue
            .unwritten()
            .requeue(vec![first.clone(), second.clone()]);
        let mut stripped = second.clone();
        stripped.as_object_mut().unwrap().remove("remember");
        let mut paged = queue
            .acknowledge_and_peek(None, None, DEFAULT_DRAIN_RECORDS)
            .records;
        let sequence = paged[1].seq;
        keep_handed_back(&queue, &mut paged, &[(sequence, stripped.clone())]);
        assert_eq!(paged.len(), 1);
        assert!(has_unfinished_records(&paged, ""));
        let retried = queue
            .acknowledge_and_peek(None, None, DEFAULT_DRAIN_RECORDS)
            .records;
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0].record, stripped);
    }

    #[test]
    fn a_batch_acknowledges_the_queue_across_page_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        let queue = DirectEvidenceQueue::default();
        for sequence in 0..=DEFAULT_DRAIN_RECORDS {
            assert!(queue.offer(json!({ "test_sequence": sequence })));
        }
        let bytes = commit_batch(
            &queue,
            false,
            Instant::now() + Duration::from_secs(2),
            || commit_queued(home, &queue, None),
        )
        .unwrap();
        let batch: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(batch["pages"], 2);
        assert_eq!(batch["record_count"], DEFAULT_DRAIN_RECORDS + 1);
        assert_eq!(batch["more"], false);
        assert_eq!(commit_queued(home, &queue, None).unwrap().record_count, 0);
    }

    #[test]
    fn a_poll_stops_at_the_page_limit_and_shutdown_finishes_the_queue() {
        let queue = DirectEvidenceQueue::default();
        let mut remaining = 10;
        let mut next = || {
            remaining -= 1;
            Ok(CommittedPage {
                record_count: 2,
                remaining,
                store_fatal: Some(Value::Null),
            })
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let batch: Value =
            serde_json::from_slice(&commit_batch(&queue, false, deadline, &mut next).unwrap())
                .unwrap();
        assert_eq!(batch["pages"], 8);
        assert_eq!(batch["record_count"], 16);
        assert_eq!(batch["more"], true);

        let batch: Value =
            serde_json::from_slice(&commit_batch(&queue, true, deadline, next).unwrap()).unwrap();
        assert_eq!(batch["pages"], 2);
        assert_eq!(batch["record_count"], 4);
        assert_eq!(batch["more"], false);
    }

    #[test]
    fn a_failed_page_preserves_the_diagnostics_of_earlier_commits() {
        let queue = DirectEvidenceQueue::default();
        let mut calls = 0;
        let bytes = commit_batch(
            &queue,
            false,
            Instant::now() + Duration::from_secs(1),
            || {
                calls += 1;
                if calls == 1 {
                    Ok(CommittedPage {
                        record_count: 3,
                        remaining: 1,
                        store_fatal: None,
                    })
                } else {
                    Err(UNHANDLED.to_owned())
                }
            },
        )
        .unwrap();
        let batch: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(calls, 2);
        assert_eq!(batch["record_count"], 3);
        assert_eq!(batch["pages"], 1);
        assert_eq!(batch["failed"], true);
        assert_eq!(batch["more"], false);
    }
}
