//! Which receipts one `hol-guard sync` uploads (`runner.sync_receipts`): the
//! rows past the saved cursor, plus a page of older receipts whose command
//! detail Guard Cloud has not seen yet when the redaction level hides less
//! than `full`.
//!
//! The store is reached through a `call(method, args)` closure so the
//! selection can be tested without a database.

use std::collections::HashSet;
use std::ops::Range;

use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::SyncError;
use crate::cloud_event_sync::EVENTS_BODY_LIMIT;
use crate::cloud_receipt_upload::UploadRequest;

/// `_RECEIPT_SYNC_BATCH_SIZE`.
pub(crate) const BATCH_SIZE: usize = 50;
/// `_RECEIPT_SYNC_CURSOR_PAGE_SIZE`.
const CURSOR_PAGE_SIZE: i64 = 200;
/// `_RECEIPT_SYNC_CURSOR_BACKFILL_ROWS`.
const CURSOR_BACKFILL_ROWS: i64 = 200;
/// `_RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS` / `_LIMIT`.
const DETAIL_BACKFILL_DAYS: i64 = 30;
const DETAIL_BACKFILL_LIMIT: i64 = 200;
pub(crate) const CURSOR_KEY: &str = "receipt_sync_cursor";
pub(crate) const DETAIL_BACKFILL_MARKER: &str = "cloud_receipt_command_detail_backfill_v2";
/// Marks a row that rides along only for its command detail. It never moves
/// the cursor.
pub(crate) const DETAIL_BACKFILL_FLAG: &str = "__command_detail_backfill";

/// The receipts one sync uploads, fixed on its first broker round.
#[derive(Debug, Clone, Default)]
pub(crate) struct Plan {
    pub(crate) rows: Vec<Value>,
    /// Receipts selected past the cursor; only these advance it.
    pub(crate) cursor_ids: HashSet<String>,
    pub(crate) prior_cursor: Option<i64>,
    /// The command-detail backfill marker, when a backfill runs.
    pub(crate) marker: Option<Value>,
    pub(crate) batches: Vec<Range<usize>>,
    /// Each row's upload payload, or `None` for a receipt too large to send
    /// in any request. Such a receipt rides in its batch unsent, so it still
    /// moves the cursor and never blocks the receipts after it.
    pub(crate) projected: Vec<Option<Value>>,
}

/// `_receipt_sync_cursor_rowid`.
pub(crate) fn cursor_rowid(saved: Option<&Value>) -> Option<i64> {
    match saved?.get("last_rowid")? {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => {
            let text = text.trim();
            if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
                text.parse().ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(crate) fn rowid(row: &Value) -> Option<i64> {
    row.get("receipt_rowid").and_then(Value::as_i64)
}

fn receipt_id(row: &Value) -> Option<&str> {
    row.get("receipt_id").and_then(Value::as_str)
}

fn rows_of(value: Value) -> Vec<Value> {
    match value {
        Value::Array(rows) => rows,
        _ => Vec::new(),
    }
}

/// `_receipt_sync_rows_for_upload`.
pub(crate) fn rows_for_upload(
    call: &dyn Fn(&str, Value) -> Result<Value, SyncError>,
    cursor: Option<i64>,
) -> Result<Vec<Value>, SyncError> {
    let since = |after: i64| {
        call(
            "list_receipts_since_rowid",
            json!({"after_rowid": after, "limit": CURSOR_PAGE_SIZE, "harness": null}),
        )
        .map(rows_of)
    };
    let Some(cursor) = cursor else {
        // The first page reads its window in rowid order from the oldest
        // receipt the newest page names, so the cursor saved after it never
        // skips a row the store left out of a shortened page.
        let newest = rows_of(call(
            "list_receipts",
            json!({"limit": CURSOR_PAGE_SIZE, "harness": null}),
        )?);
        return match newest.iter().filter_map(rowid).min() {
            Some(oldest) => since((oldest - 1).max(0)),
            None => Ok(newest),
        };
    };
    let Some(latest) = call("latest_receipt_rowid", json!({"harness": null}))?.as_i64() else {
        return Ok(Vec::new());
    };
    if cursor > latest {
        // The store was reset below the cursor; resend its newest window.
        return since((latest - CURSOR_BACKFILL_ROWS).max(0));
    }
    since(cursor)
}

/// `_receipt_command_detail_backfill_before_rowid`.
fn backfill_before_rowid(marker: Option<&Value>, level: &str) -> Option<i64> {
    let marker = marker?.as_object()?;
    if marker.get("level").and_then(Value::as_str) != Some(level) {
        return None;
    }
    let value = match marker.get("before_rowid")? {
        Value::Number(number) => number.as_i64()?,
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            text.parse().ok()?
        }
        _ => return None,
    };
    (value > 0).then_some(value)
}

/// `_receipt_sync_rows_with_command_detail_backfill`: the rows with older
/// receipts appended, and the marker to save as they are delivered.
pub(crate) fn with_detail_backfill(
    call: &dyn Fn(&str, Value) -> Result<Value, SyncError>,
    saved_marker: Option<&Value>,
    rows: Vec<Value>,
    level: &str,
    now: &str,
) -> Result<(Vec<Value>, Option<Value>), SyncError> {
    // Only a level that hides less than `full` has detail to backfill.
    if !matches!(level, "partial" | "none") {
        return Ok((rows, None));
    }
    let before = backfill_before_rowid(saved_marker, level);
    if saved_marker.is_some_and(|marker| {
        marker.get("level").and_then(Value::as_str) == Some(level)
            && marker.get("complete") == Some(&Value::Bool(true))
    }) {
        return Ok((rows, None));
    }
    let backfill = rows_of(call(
        "list_receipts_for_command_detail_backfill",
        json!({
            "limit": DETAIL_BACKFILL_LIMIT,
            "days": DETAIL_BACKFILL_DAYS,
            "before_rowid": before,
            "now": now,
        }),
    )?);
    let mut seen: HashSet<String> = rows
        .iter()
        .filter_map(receipt_id)
        .map(str::to_owned)
        .collect();
    let mut merged = rows;
    let mut added = 0_usize;
    for row in &backfill {
        let Some(id) = receipt_id(row) else { continue };
        if !seen.insert(id.to_owned()) {
            continue;
        }
        let mut flagged = row.clone();
        if let Some(object) = flagged.as_object_mut() {
            object.insert(DETAIL_BACKFILL_FLAG.to_owned(), Value::Bool(true));
        }
        merged.push(flagged);
        added += 1;
    }
    let next_before = backfill.iter().filter_map(rowid).min().or(before);
    // Only an empty page ends the backfill: a page the store shortened is not
    // the end, and each page moves `before_rowid` down, so the walk finishes.
    let marker = json!({
        "level": level,
        "updated_at": now,
        "days": DETAIL_BACKFILL_DAYS,
        "limit": DETAIL_BACKFILL_LIMIT,
        "receipts": added,
        "queried": backfill.len(),
        "before_rowid": next_before,
        "complete": backfill.is_empty(),
    });
    Ok((merged, Some(marker)))
}

/// `_advance_command_detail_backfill_marker` for one delivered batch.
pub(crate) fn advance_marker(marker: &Value, batch: &[Value], synced_at: &str) -> Option<Value> {
    let lowest = batch
        .iter()
        .filter(|row| row.get(DETAIL_BACKFILL_FLAG) == Some(&Value::Bool(true)))
        .filter_map(rowid)
        .min()?;
    let mut updated: Map<String, Value> = marker.as_object()?.clone();
    updated.insert("before_rowid".to_owned(), json!(lowest));
    updated.insert("updated_at".to_owned(), json!(synced_at));
    Some(Value::Object(updated))
}

/// `_iter_receipt_sync_batches`: an empty upload still sends one request,
/// which carries the sync context.
pub(crate) fn batches(count: usize) -> Vec<Range<usize>> {
    if count == 0 {
        return std::iter::once(0..0).collect();
    }
    (0..count)
        .step_by(BATCH_SIZE)
        .map(|start| start..(start + BATCH_SIZE).min(count))
        .collect()
}

/// Split the rows so no request body goes over `limit` bytes. `sizes` holds
/// each payload's serialized length, `None` for one that is not sent;
/// `overhead` is the body without any receipts, and `first_overhead` the
/// first request's, which also carries the fleet posture. A receipt that does
/// not fit beside the posture closes the first request, so the posture goes
/// on its own. A batch still holds at most [`BATCH_SIZE`] rows.
pub(crate) fn sized_batches(
    sizes: &[Option<usize>],
    first_overhead: usize,
    overhead: usize,
    limit: usize,
) -> Vec<Range<usize>> {
    if sizes.is_empty() {
        return std::iter::once(0..0).collect();
    }
    let mut ranges = Vec::new();
    let (mut start, mut bytes, mut sent) = (0, first_overhead, 0_usize);
    for (index, size) in sizes.iter().enumerate() {
        // Each payload after the first adds a separating comma.
        let added = size.map(|size| size + usize::from(sent > 0));
        let full = index - start == BATCH_SIZE
            || added.is_some_and(|added| {
                (sent > 0 || ranges.is_empty() && first_overhead > overhead)
                    && bytes + added > limit
            });
        if full {
            ranges.push(start..index);
            (start, bytes, sent) = (index, overhead, 0);
        }
        if let Some(size) = size {
            bytes += size + usize::from(sent > 0);
            sent += 1;
        }
    }
    ranges.push(start..sizes.len());
    ranges
}

/// The `receipt_cursor_backfill` summary flag: a sync that had a cursor
/// uploaded receipts, none of them past it.
pub(crate) fn cursor_backfill(plan: &Plan) -> bool {
    let Some(prior) = plan.prior_cursor else {
        return false;
    };
    !plan.rows.is_empty() && !plan.rows.iter().filter_map(rowid).any(|id| id > prior)
}

/// Select the rows and fix the batches for one sync.
pub(crate) fn plan(
    call: &dyn Fn(&str, Value) -> Result<Value, SyncError>,
    saved_cursor: Option<&Value>,
    saved_marker: Option<&Value>,
    level: &str,
    now: &str,
) -> Result<Plan, SyncError> {
    let prior_cursor = cursor_rowid(saved_cursor);
    let rows = rows_for_upload(call, prior_cursor)?;
    let cursor_ids = rows
        .iter()
        .filter_map(receipt_id)
        .map(str::to_owned)
        .collect();
    let (rows, marker) = with_detail_backfill(call, saved_marker, rows, level, now)?;
    let batches = batches(rows.len());
    Ok(Plan {
        rows,
        cursor_ids,
        prior_cursor,
        marker,
        batches,
        projected: Vec::new(),
    })
}

/// The receipts' upload payloads, and batches whose bodies fit through the
/// egress broker. A receipt too large for a request of its own is left out
/// of every body.
pub(crate) fn fit_to_broker(request: &UploadRequest, mut plan: Plan) -> Result<Plan, SyncError> {
    let projected = crate::cloud_receipt_payload::cloud_sync_receipt_payloads(&json!({
        "receipts": plan.rows,
        "device_id": request.device_id,
        "device_name": request.device_name,
        "redaction_level": request.redaction_level,
        "now": request.now,
    }))
    .map_err(|error| SyncError::Failed(format!("Guard receipts could not be prepared: {error}")))?;
    let payloads = match projected.get("payloads") {
        Some(Value::Array(payloads)) if payloads.len() == plan.rows.len() => payloads.clone(),
        _ => {
            return Err(SyncError::Failed(
                "Guard receipts could not be prepared.".to_owned(),
            ))
        }
    };
    let body_size = |context: &Map<String, Value>| {
        json!({"receipts": [], "syncContext": context})
            .to_string()
            .len()
    };
    let overhead = body_size(&request.sync_context);
    // The first request also carries the posture.
    let first_overhead = request.fleet_posture.as_ref().map_or(overhead, |posture| {
        let mut context = request.sync_context.clone();
        context.insert("fleetPosture".to_owned(), posture.payload.clone());
        body_size(&context)
    });
    let (projected, sizes): (Vec<Option<Value>>, Vec<Option<usize>>) = payloads
        .into_iter()
        .map(|payload| {
            let size = payload.to_string().len();
            let fits = overhead + size <= EVENTS_BODY_LIMIT;
            (fits.then_some(payload), fits.then_some(size))
        })
        .unzip();
    plan.batches = sized_batches(&sizes, first_overhead, overhead, EVENTS_BODY_LIMIT);
    plan.projected = projected;
    Ok(plan)
}
