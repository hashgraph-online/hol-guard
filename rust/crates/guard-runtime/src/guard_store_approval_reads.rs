//! Approval queue reads: `GuardStore.get_approval_request` and
//! `GuardStore.list_approval_requests`. Every row is projected to its
//! canonical surfaces and, unless the caller reads the stored draft only,
//! carries the scope contract the resident derives for it.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_approval_page_reads::{Filter, ORDER};
use crate::guard_store_approval_read_rows::draft;
use crate::guard_store_approval_read_scope::{project, scope_contract, unavailable};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, Row, StoreResult};

pub(crate) const COLUMNS: &str = "request_id, harness, artifact_id, artifact_name, artifact_type, \
     artifact_hash, publisher, policy_action, recommended_scope, changed_fields_json, \
     source_scope, oauth_source, config_path, workspace, launch_target, \
     normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at, \
     transport, risk_summary, risk_signals_json, artifact_label, source_label, \
     trigger_summary, why_now, launch_summary, risk_headline, action_envelope_json, \
     decision_v2_json, fallback_cli_command, scanner_evidence_json, watch_only_observation, \
     browser_intent_json, continuation_snapshot_json, review_command, approval_url, status, \
     resolution_action, resolution_scope, reason, created_at, resolved_at, raw_command_text, \
     guard_version, first_seen_guard_version, last_seen_guard_version";
const SUPERSEDED_PREFIX: &str = "superseded_by_fresh_review:";
/// Rows one list call reads, and the payload bytes it returns before the
/// caller asks for the rest; the reply must stay under the resident cap.
const PAGE_ROWS: i64 = 128;
pub(crate) const PAGE_BYTES: usize = 1536 * 1024;

/// `get_approval_request(request_id, derive_scope=...)`.
pub(crate) fn get_approval_request(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let Some(row) = query_one(
        connection,
        &format!("select {COLUMNS} from approval_requests where request_id = ?"),
        &[Value::from(args.str("request_id")?)],
    )?
    else {
        return Ok(Value::Null);
    };
    let projection = project(&row, guard_home)?;
    let mut built = if args.flag("derive_scope")? {
        payloads(vec![(&row, projection)], args.opt_str("cwd")?)?
    } else {
        let (mut payload, contract_error) = draft(&row, &projection)?;
        if let Some(error) = contract_error {
            payload.insert("decision_contract_error".to_owned(), Value::String(error));
        }
        vec![payload]
    };
    let mut payload = built.remove(0);
    if let Some(replacement) = superseded_by(connection, guard_home, &row)? {
        payload.insert(
            "superseded_by_request_id".to_owned(),
            Value::String(replacement),
        );
    }
    Ok(Value::Object(payload))
}

/// `list_approval_requests(status, harness, limit, cursor, search)` as
/// bounded chunks: `{"items": [...], "complete": bool}`. An incomplete chunk
/// also carries `after`, the sort key of its last item; the caller passes it
/// back with `taken`, the items it holds, so rows that move or arrive between
/// chunks are neither repeated nor skipped the way an offset would.
pub(crate) fn list_approval_requests(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let limit = args.raw("limit").map(|_| args.int("limit")).transpose()?;
    let taken = args.raw("taken").map_or(Ok(0), |_| args.int("taken"))?;
    let remaining = limit
        .filter(|limit| *limit >= 0)
        .map(|limit| (limit - taken).max(0));
    let page = remaining.map_or(PAGE_ROWS, |remaining| remaining.min(PAGE_ROWS));
    let mut filter = Filter::default();
    filter.equals("status", args.opt_str("status")?);
    filter.equals("harness", args.opt_str("harness")?);
    filter.after(args.strings("cursor")?)?;
    filter.continue_after(args.raw("after"))?;
    filter.search(args.opt_str("search")?);
    let (filter, mut params) = filter.finish();
    params.push(Value::from(page));
    let rows = query_all(
        connection,
        &format!("select {COLUMNS} from approval_requests {filter} {ORDER} limit ?"),
        &params,
    )?;
    let cwd = args.opt_str("cwd")?;
    let mut returned = Vec::new();
    let mut bytes = 0;
    // Rows project one at a time so a chunk stops at its byte budget without
    // projecting rows the next chunk reads again.
    for row in &rows {
        let projection = project(row, guard_home)?;
        let item = payloads(vec![(row, projection)], cwd)?.remove(0);
        bytes += serde_json::to_vec(&item).map_or(0, |encoded| encoded.len());
        if !returned.is_empty() && bytes > PAGE_BYTES {
            break;
        }
        returned.push(Value::Object(item));
    }
    let reached_limit = remaining.is_some_and(|remaining| returned.len() as i64 >= remaining);
    if returned.len() < rows.len() || (rows.len() as i64 == page && !reached_limit) {
        let after = continuation(&rows[returned.len() - 1]);
        return Ok(json!({"items": returned, "complete": false, "after": after}));
    }
    Ok(json!({"items": returned, "complete": true}))
}

/// The sort key a chunk's caller passes back as `after` to read on from
/// `row`.
pub(crate) fn continuation(row: &Row) -> Value {
    json!([row.get("last_seen_at"), row.get("request_id")])
}

/// `_rows_to_payloads` for projected rows: drafts first, then each draft's
/// scope contract and its legacy scope surfaces.
pub(crate) fn payloads(
    rows: Vec<(&Row, Value)>,
    cwd: Option<&str>,
) -> StoreResult<Vec<Map<String, Value>>> {
    let drafts = rows
        .iter()
        .map(|(row, projection)| draft(row, projection))
        .collect::<StoreResult<Vec<_>>>()?;
    let contracts = drafts
        .iter()
        .map(|(payload, _)| scope_contract(payload, cwd))
        .collect::<StoreResult<Vec<_>>>()?;
    let mut payloads = Vec::with_capacity(drafts.len());
    for ((mut payload, contract_error), contract) in drafts.into_iter().zip(contracts) {
        payload.extend(contract);
        if let Some(error) = contract_error {
            payload.insert("decision_contract_error".to_owned(), Value::String(error));
        }
        apply_scope_surfaces(&mut payload)?;
        payloads.push(payload);
    }
    Ok(payloads)
}

/// `approval_scope_support.apply_scope_surfaces`.
fn apply_scope_surfaces(payload: &mut Map<String, Value>) -> StoreResult<()> {
    let (Some(Value::Object(allowed)), Some(Value::Object(recommended))) = (
        payload.get("allowed_scopes_by_action"),
        payload.get("recommended_scope_by_action"),
    ) else {
        return Err(unavailable());
    };
    let Some(allowed) = allowed
        .get("allow")
        .filter(|scopes| scopes.is_array())
        .cloned()
    else {
        return Err(unavailable());
    };
    let recommended = recommended.get("allow").cloned().unwrap_or(Value::Null);
    payload.insert("recommended_scope".to_owned(), recommended);
    if let Some(Value::Object(decision)) = payload.get_mut("decision_v2_json") {
        decision.insert("approval_scopes".to_owned(), allowed.clone());
    }
    payload.insert("allowed_scopes".to_owned(), allowed);
    Ok(())
}

/// The pending request that superseded an expired one, when it still
/// matches the expired request's queue identity and projects cleanly.
fn superseded_by(
    connection: &Connection,
    guard_home: &str,
    row: &Row,
) -> StoreResult<Option<String>> {
    let replacement = match (row.get("status"), row.get("reason")) {
        (Some(Value::String(status)), Some(Value::String(reason))) if status == "expired" => {
            reason.strip_prefix(SUPERSEDED_PREFIX)
        }
        _ => None,
    };
    let Some(replacement) = replacement.filter(|replacement| {
        (1..=64).contains(&replacement.len())
            && replacement
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) else {
        return Ok(None);
    };
    let field = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
    let candidate = query_one(
        connection,
        "select policy_action, decision_v2_json, action_envelope_json from approval_requests \
         where request_id = ? and status = 'pending' and harness = ? and artifact_id = ? \
         and workspace IS ? and oauth_source IS ? and queue_group_id IS ?",
        &[
            Value::from(replacement),
            field("harness"),
            field("artifact_id"),
            field("workspace"),
            field("oauth_source"),
            field("queue_group_id"),
        ],
    )?;
    match candidate {
        Some(candidate) if project(&candidate, guard_home)?["contract_error"].is_null() => {
            Ok(Some(replacement.to_owned()))
        }
        _ => Ok(None),
    }
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_reads_tests.rs"]
pub(crate) mod tests;
