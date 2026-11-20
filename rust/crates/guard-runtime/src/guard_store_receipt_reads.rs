//! Receipt read methods. Every returned receipt carries the final canonical
//! action derived in the resident from all persisted authorities.

use std::collections::BTreeMap;

use guard_contracts::MAX_NATIVE_RESPONSE_BYTES;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    int, is_null, query_all, query_one, text, value_error, Row, StoreResult,
};
use crate::guard_store_json::add_seconds_isoformat;
use crate::guard_store_receipt_analytics::load as load_analytics;
use crate::guard_store_receipt_approval::ActionInputs;
use crate::guard_store_receipt_decision::{
    action_value, canonical_receipt_decision, canonical_rollup_action, compose, stored_checks,
};
use crate::guard_store_receipt_events::reconcile_pending_events;
use crate::guard_store_receipt_rollups::{count_from_rollups, rebuild_if_pending, refresh};

pub(crate) const BASE_QUERY: &str = "select r.rowid as receipt_rowid, r.receipt_id, r.harness, \
     r.artifact_id, r.artifact_hash, r.policy_decision, r.capabilities_summary, \
     r.changed_capabilities_json, r.provenance_summary, r.user_override, r.artifact_name, \
     r.source_scope, r.scanner_evidence_json, r.diff_summary, r.approval_source, \
     r.approval_request_id, r.timestamp, r.raw_command_text, \
     e.envelope_full_json as envelope_full_json, \
     e.envelope_redacted_json as envelope_redacted_json, \
     a.request_id as linked_approval_request_id, a.status as approval_status, \
     a.resolution_action as approval_resolution_action, \
     a.resolved_at as approval_resolved_at, a.policy_action as approval_policy_action, \
     a.decision_v2_json as approval_decision_v2_json, \
     a.action_envelope_json as approval_envelope_json \
     from runtime_receipts r \
     left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id \
     left join approval_requests a on a.request_id = r.approval_request_id \
     left join receipt_rollup_actions s on s.receipt_id = r.receipt_id";

fn cell(row: &Row, name: &str) -> Value {
    row.get(name).cloned().unwrap_or(Value::Null)
}

fn scanner_evidence(raw: &Value) -> Value {
    let Some(raw) = raw.as_str() else {
        return json!([]);
    };
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(items)) => Value::Array(
            items
                .into_iter()
                .filter(Value::is_object)
                .collect::<Vec<_>>(),
        ),
        _ => json!([]),
    }
}

/// `_receipt_dict_from_row`.
fn receipt_dict(row: &Row, include_rowid: bool) -> StoreResult<Value> {
    let inputs = ActionInputs::from_row(row);
    let checks = stored_checks(&inputs)?;
    let approval = inputs.linked_authority()?;
    let final_policy = compose(&checks, &approval);
    let final_value = action_value(final_policy);
    let output_envelope = checks
        .full
        .envelope
        .clone()
        .or_else(|| approval.envelope.clone())
        .map_or(Value::Null, Value::Object);
    let envelope = canonical_receipt_decision(&final_value, &output_envelope, false)?;
    let redacted =
        canonical_receipt_decision(&final_value, &checks.redacted.envelope_value(), false)?;
    let raw_capabilities = text(row, "changed_capabilities_json");
    let Ok(changed_capabilities) = serde_json::from_str::<Value>(raw_capabilities) else {
        return value_error("native_guard_store_receipt_capabilities_invalid");
    };
    let mut result = Map::new();
    if include_rowid {
        result.insert("receipt_rowid".into(), json!(int(row, "receipt_rowid")));
    }
    for key in [
        "receipt_id",
        "harness",
        "artifact_id",
        "artifact_hash",
        "capabilities_summary",
        "provenance_summary",
        "timestamp",
    ] {
        result.insert(key.into(), Value::from(text(row, key)));
    }
    for key in [
        "user_override",
        "artifact_name",
        "source_scope",
        "diff_summary",
        "approval_source",
        "approval_request_id",
        "raw_command_text",
    ] {
        result.insert(key.into(), cell(row, key));
    }
    result.insert("policy_decision".into(), final_value);
    result.insert("changed_capabilities".into(), changed_capabilities);
    result.insert(
        "scanner_evidence".into(),
        scanner_evidence(&cell(row, "scanner_evidence_json")),
    );
    result.insert("action_envelope_json".into(), envelope.envelope_value());
    result.insert("envelope_redacted_json".into(), redacted.envelope_value());
    if checks.stored.contract_error
        || checks.full.contract_error
        || checks.redacted.contract_error
        || approval.contract_error
    {
        result.insert(
            "decision_contract_error".into(),
            Value::from(guard_contracts::AUTHORITATIVE_DECISION_INCONSISTENT),
        );
    }
    Ok(Value::Object(result))
}

/// A receipt list stops here so one long history cannot build a reply the
/// resident has to refuse, which the caller only ever sees as the store being
/// unavailable. The slack covers the envelope the reply is framed in. Every
/// list below is ordered, so truncation drops the far end: the oldest rows of
/// a newest-first read, and rows a cursor page returns on its next call.
const LIST_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 128 * 1024;

fn receipts(rows: &[Row], include_rowid: bool) -> StoreResult<Value> {
    let mut listed = Vec::new();
    let mut bytes = 0;
    for row in rows {
        let item = receipt_dict(row, include_rowid)?;
        bytes += serde_json::to_vec(&item).map_or(0, |encoded| encoded.len());
        // One row over the budget still comes back, so a cursor page always
        // advances past it rather than stalling on a receipt it cannot skip.
        if !listed.is_empty() && bytes > LIST_BUDGET_BYTES {
            break;
        }
        listed.push(item);
    }
    Ok(Value::Array(listed))
}

fn single(row: Option<Row>) -> StoreResult<Value> {
    row.map_or(Ok(Value::Null), |row| receipt_dict(&row, false))
}

fn harness_arg(args: &Args<'_>) -> StoreResult<Option<Value>> {
    Ok(args.opt_str("harness")?.map(Value::from))
}

pub(crate) fn list_receipts(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let limit = Value::from(args.int("limit")?);
    let rows = match harness_arg(args)? {
        Some(harness) => query_all(
            connection,
            &format!("{BASE_QUERY} where r.harness = ? order by r.timestamp desc limit ?"),
            &[harness, limit],
        )?,
        None => query_all(
            connection,
            &format!("{BASE_QUERY} order by r.timestamp desc limit ?"),
            &[limit],
        )?,
    };
    receipts(&rows, true)
}

pub(crate) fn list_since_rowid(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let after = Value::from(
        args.raw("after_rowid")
            .map_or(Ok(0), |_| args.int("after_rowid"))?,
    );
    let limit = Value::from(args.int("limit")?);
    let rows = match harness_arg(args)? {
        Some(harness) => query_all(
            connection,
            &format!(
                "{BASE_QUERY} where r.rowid > ? and r.harness = ? order by r.rowid asc limit ?"
            ),
            &[after, harness, limit],
        )?,
        None => query_all(
            connection,
            &format!("{BASE_QUERY} where r.rowid > ? order by r.rowid asc limit ?"),
            &[after, limit],
        )?,
    };
    receipts(&rows, true)
}

pub(crate) fn list_for_command_detail_backfill(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let days = args.int("days")?.max(1);
    let Some(cutoff) = add_seconds_isoformat(args.str("now")?, -days * 86_400 * 1_000_000) else {
        return value_error("native_guard_store_invalid_now");
    };
    let limit = args.int("limit")?.max(1);
    refresh(connection)?;
    let before = args
        .raw("before_rowid")
        .map(|_| args.int("before_rowid"))
        .transpose()?;
    let clause = if before.is_some() {
        "and r.rowid < ?"
    } else {
        ""
    };
    let sql = format!(
        "{BASE_QUERY} where r.timestamp >= ? \
         and s.policy_decision in ('block', 'review', 'require-reapproval', 'sandbox-required') \
         and (e.envelope_full_json is not null or a.action_envelope_json is not null) \
         {clause} order by r.rowid desc limit ?"
    );
    let mut params = vec![Value::from(cutoff)];
    params.extend(before.map(Value::from));
    params.push(Value::from(limit));
    receipts(&query_all(connection, &sql, &params)?, true)
}

pub(crate) fn latest_rowid(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let row = match harness_arg(args)? {
        Some(harness) => query_one(
            connection,
            "select max(rowid) as max_rowid from runtime_receipts where harness = ?",
            &[harness],
        )?,
        None => query_one(
            connection,
            "select max(rowid) as max_rowid from runtime_receipts",
            &[],
        )?,
    };
    Ok(row
        .filter(|row| !is_null(row, "max_rowid"))
        .map_or(Value::Null, |row| json!(int(&row, "max_rowid"))))
}

pub(crate) fn get_receipt(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    single(query_one(
        connection,
        &format!("{BASE_QUERY} where r.receipt_id = ?"),
        &[Value::from(args.str("receipt_id")?)],
    )?)
}

pub(crate) fn get_for_approval_request(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    single(query_one(
        connection,
        &format!(
            "{BASE_QUERY} where r.approval_request_id = ? and r.policy_decision = ? \
             order by r.rowid asc limit 1"
        ),
        &[
            Value::from(args.str("request_id")?),
            Value::from(args.str("policy_decision")?),
        ],
    )?)
}

pub(crate) fn get_latest(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    single(query_one(
        connection,
        &format!(
            "{BASE_QUERY} where r.harness = ? and r.artifact_id = ? \
             order by r.timestamp desc limit 1"
        ),
        &[
            Value::from(args.str("harness")?),
            Value::from(args.str("artifact_id")?),
        ],
    )?)
}

pub(crate) fn count(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let harness = args.opt_str("harness")?;
    rebuild_if_pending(connection)?;
    if let Some(total) = count_from_rollups(connection, harness)? {
        return Ok(json!(total));
    }
    let row = match harness {
        Some(harness) => query_one(
            connection,
            "select count(*) as total from runtime_receipts where harness = ?",
            &[Value::from(harness)],
        )?,
        None => query_one(
            connection,
            "select count(*) as total from runtime_receipts",
            &[],
        )?,
    };
    Ok(json!(row.map_or(0, |row| int(&row, "total"))))
}

pub(crate) fn summary_between(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    refresh(connection)?;
    let row = query_one(
        connection,
        "select count(*) as total, \
         coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0) as blocked, \
         coalesce(sum(case when s.policy_decision in ('allow', 'warn') then 1 else 0 end), 0) \
           as approved, \
         (select max(timestamp) from runtime_receipts) as latest_at \
         from runtime_receipts r join receipt_rollup_actions s on s.receipt_id = r.receipt_id \
         where r.timestamp >= ? and r.timestamp < ?",
        &[
            Value::from(args.str("start_at")?),
            Value::from(args.str("before_at")?),
        ],
    )?;
    let Some(row) = row else {
        return Ok(json!({"total": 0, "blocked": 0, "approved": 0, "latest_at": null}));
    };
    let latest = cell(&row, "latest_at");
    let latest = latest
        .as_str()
        .filter(|text| !text.is_empty())
        .map_or(Value::Null, Value::from);
    Ok(json!({
        "total": int(&row, "total"), "blocked": int(&row, "blocked"),
        "approved": int(&row, "approved"), "latest_at": latest,
    }))
}

pub(crate) fn analytics(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let activity_days = args.int("activity_days")?.clamp(1, 366);
    let trend_days = args.int("trend_days")?.clamp(1, activity_days);
    let top_limit = args.int("top_limit")?.clamp(1, 50);
    refresh(connection)?;
    load_analytics(
        connection,
        args.str("now")?,
        activity_days,
        trend_days,
        top_limit,
    )
}

pub(crate) fn decision_counts(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        "select r.policy_decision, e.envelope_full_json, e.envelope_redacted_json, \
         r.approval_request_id, a.request_id as linked_approval_request_id, \
         a.status as approval_status, a.resolution_action as approval_resolution_action, \
         a.resolved_at as approval_resolved_at, a.policy_action as approval_policy_action, \
         a.decision_v2_json as approval_decision_v2_json, \
         a.action_envelope_json as approval_envelope_json \
         from runtime_receipts r \
         left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id \
         left join approval_requests a on a.request_id = r.approval_request_id \
         where r.harness = ? and r.artifact_id = ?",
        &[
            Value::from(args.str("harness")?),
            Value::from(args.str("artifact_id")?),
        ],
    )?;
    let mut counts: BTreeMap<&'static str, i64> = BTreeMap::new();
    for row in &rows {
        let action = canonical_rollup_action(&ActionInputs::from_row(row))?;
        *counts.entry(action.as_str()).or_insert(0) += 1;
    }
    Ok(json!(counts))
}

pub(crate) fn reconcile_events(connection: &Connection, _args: &Args<'_>) -> StoreResult<Value> {
    refresh(connection)?;
    reconcile_pending_events(connection)?;
    Ok(Value::Null)
}
