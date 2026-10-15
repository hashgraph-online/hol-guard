//! Approval queue reads: `GuardStore.get_approval_request` and
//! `GuardStore.list_approval_requests`. Every row is projected to its
//! canonical surfaces and, unless the caller reads the stored draft only,
//! carries the scope contract the resident derives for it.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_approval_read_rows::draft;
use crate::guard_store_approval_read_scope::{project, scope_contract, unavailable};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, Row, StoreError, StoreResult};

const COLUMNS: &str = "request_id, harness, artifact_id, artifact_name, artifact_type, \
     artifact_hash, publisher, policy_action, recommended_scope, changed_fields_json, \
     source_scope, oauth_source, config_path, workspace, launch_target, \
     normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at, \
     transport, risk_summary, risk_signals_json, artifact_label, source_label, \
     trigger_summary, why_now, launch_summary, risk_headline, action_envelope_json, \
     decision_v2_json, fallback_cli_command, scanner_evidence_json, watch_only_observation, \
     browser_intent_json, continuation_snapshot_json, review_command, approval_url, status, \
     resolution_action, resolution_scope, reason, created_at, resolved_at, raw_command_text, \
     guard_version, first_seen_guard_version, last_seen_guard_version";
const SEARCH_COLUMNS: [&str; 15] = [
    "artifact_name",
    "artifact_id",
    "risk_summary",
    "risk_headline",
    "trigger_summary",
    "why_now",
    "launch_summary",
    "launch_target",
    "raw_command_text",
    "fallback_cli_command",
    "review_command",
    "action_identity",
    "action_envelope_json",
    "decision_v2_json",
    "config_path",
];
const SUPERSEDED_PREFIX: &str = "superseded_by_fresh_review:";
/// Rows one list call reads, and the payload bytes it returns before the
/// caller asks for the rest; the reply must stay under the resident cap.
const PAGE_ROWS: i64 = 128;
const PAGE_BYTES: usize = 1536 * 1024;

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
/// bounded chunks: `{"items": [...], "complete": bool, "after": key}`. The
/// caller continues an incomplete chunk by passing `after`, the sort key of
/// its last item, so rows that move or arrive between chunks are neither
/// repeated nor skipped the way an offset would.
pub(crate) fn list_approval_requests(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let limit = args.raw("limit").map(|_| args.int("limit")).transpose()?;
    let page = match limit {
        Some(limit) if limit >= 0 => limit.clamp(0, PAGE_ROWS),
        _ => PAGE_ROWS,
    };
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    for column in ["status", "harness"] {
        if let Some(value) = args.opt_str(column)? {
            clauses.push(format!("{column} = ?"));
            params.push(Value::from(value));
        }
    }
    if let Some(cursor) = args.strings("cursor")? {
        let [last_seen_at, request_id] = cursor[..] else {
            return Err(StoreError::Invalid("native_guard_store_args_invalid"));
        };
        clauses.push("(last_seen_at < ? or (last_seen_at = ? and request_id < ?))".to_owned());
        params.extend([last_seen_at, last_seen_at, request_id].map(Value::from));
    }
    if let Some(after) = args.raw("after") {
        // Rows sort newest first with a null `last_seen_at` last.
        let Some([last_seen_at, Value::String(request_id)]) = after.as_array().map(Vec::as_slice)
        else {
            return Err(StoreError::Invalid("native_guard_store_args_invalid"));
        };
        if last_seen_at.is_null() {
            clauses.push("(last_seen_at is null and request_id < ?)".to_owned());
            params.push(Value::from(request_id.as_str()));
        } else {
            clauses.push(
                "(last_seen_at < ? or last_seen_at is null \
                 or (last_seen_at = ? and request_id < ?))"
                    .to_owned(),
            );
            params.extend([
                last_seen_at.clone(),
                last_seen_at.clone(),
                Value::from(request_id.as_str()),
            ]);
        }
    }
    if let Some(search) = args.opt_str("search")? {
        let terms: Vec<String> = SEARCH_COLUMNS
            .iter()
            .map(|column| format!("lower(coalesce({column}, '')) like lower(?)"))
            .collect();
        clauses.push(format!("({})", terms.join(" or ")));
        params.extend(SEARCH_COLUMNS.map(|_| Value::from(format!("%{search}%"))));
    }
    let filter = if clauses.is_empty() {
        String::new()
    } else {
        format!("where {}", clauses.join(" and "))
    };
    params.push(Value::from(page));
    let rows = query_all(
        connection,
        &format!(
            "select {COLUMNS} from approval_requests {filter} \
             order by last_seen_at desc, request_id desc limit ?"
        ),
        &params,
    )?;
    let cwd = args.opt_str("cwd")?;
    let mut returned = Vec::new();
    let mut after = Value::Null;
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
        after = json!([row.get("last_seen_at"), row.get("request_id")]);
    }
    let reached_limit = limit.is_some_and(|limit| limit >= 0 && returned.len() as i64 >= limit);
    let complete = returned.len() == rows.len() && (rows.len() < page as usize || reached_limit);
    Ok(json!({"items": returned, "complete": complete, "after": after}))
}

/// `_rows_to_payloads` for projected rows: drafts first, then each draft's
/// scope contract and its legacy scope surfaces.
fn payloads(rows: Vec<(&Row, Value)>, cwd: Option<&str>) -> StoreResult<Vec<Map<String, Value>>> {
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
mod tests;
