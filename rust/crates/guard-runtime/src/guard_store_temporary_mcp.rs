//! `GuardStore.apply_temporary_mcp_grant_resolution`: a routine browser MCP
//! capability granted for a bounded time, and the pending requests that grant
//! makes obsolete, settled in one write transaction.
//!
//! The caller decides the grant - which server, which category, how long - and
//! this writes it: the policy decision, the request that asked for it, and
//! every other pending request the grant now answers. Splitting those writes
//! would leave a window where the grant exists while the requests it covers
//! still block, or where those requests are cleared and the grant is not there.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::context_digest::python_strip;
use crate::guard_store_approval_page_reads::ORDER;
use crate::guard_store_approval_queue_result::{
    block_reason, fits, queue_result, request, unresolved,
};
use crate::guard_store_approval_read_scope::project;
use crate::guard_store_approval_reads::{payloads, COLUMNS};
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, value_error, StoreResult};
use crate::guard_store_policy_upsert::upsert_policy;
use crate::mcp_tool_policy_grants::{category_for, INFORMATIONAL_CATEGORY};
use crate::policy_store::PolicySnapshotStore;

/// A temporary grant resolves its request the way the dashboard resolves an
/// artifact approval.
const RESOLUTION_ACTION: &str = "allow";
const RESOLUTION_SCOPE: &str = "artifact";

/// The fields a caller may not spell on the decision: the transaction supplies
/// them, so a caller that sent its own would write at a time or a generation
/// the resident did not choose.
const DECISION_RESERVED: [&str; 4] = [
    "now",
    "current_generation",
    "integrity_key_b64",
    "integrity_key_id",
];

/// `apply_temporary_mcp_grant_resolution`.
pub(crate) fn apply_temporary_mcp_grant(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let resolved_at = args.str("resolved_at")?;
    let reason = args.opt_str("reason")?;
    let cwd = args.opt_str("cwd")?;

    let Value::Object(fields) = request(connection, guard_home, request_id, cwd, owner)? else {
        return settled(
            unresolved(connection, guard_home, cwd, "not_found", Value::Null, owner)?,
            Vec::new(),
            Value::Null,
        );
    };
    let source = Value::Object(fields);
    if source["status"] != "pending" {
        return settled(
            unresolved(
                connection,
                guard_home,
                cwd,
                "already_resolved",
                source,
                owner,
            )?,
            Vec::new(),
            Value::Null,
        );
    }
    // `require_resolvable_approval_request`: a terminal or contract-invalid row
    // is a caller contract error here, not a queue answer, so nothing is
    // written and the caller raises on the reason.
    if let Some(reason) = block_reason(&source) {
        return Ok(json!({ "blocked": reason }));
    }

    let covered = covered_request_ids(connection, guard_home, request_id, &source, args, owner)?;
    let next_control_state = write_decision(connection, args, resolved_at)?;
    let resolution = [
        Value::from(RESOLUTION_ACTION),
        Value::from(RESOLUTION_SCOPE),
        Value::from(reason),
        Value::from(resolved_at),
    ];
    let result = queue_result(connection, guard_home, request_id, &resolution, cwd, owner)?;
    resolve_covered(connection, &covered, &resolution)?;
    settled(result, covered, next_control_state)
}

/// The reply: what the queue says now, which other requests the grant
/// answered, and the integrity state the caller finalizes after the commit.
///
/// It goes through the same size check as every other queue-resolving reply.
/// A grant covering a large pending queue can outgrow the response budget, and
/// failing here rolls the whole resolution back rather than committing a grant
/// whose answer the dashboard never receives.
fn settled(result: Value, covered: Vec<String>, next_control_state: Value) -> StoreResult<Value> {
    fits(json!({
        "result": result,
        "covered_request_ids": covered,
        "next_control_state": next_control_state,
    }))
}

/// The grant's policy decision. `upsert_policy` owns the row and its signing;
/// this only supplies the time and the integrity material, which belong to the
/// transaction rather than to the decision the caller sent.
fn write_decision(
    connection: &Connection,
    args: &Args<'_>,
    resolved_at: &str,
) -> StoreResult<Value> {
    let decision = args.object("decision")?;
    if decision
        .keys()
        .any(|name| DECISION_RESERVED.contains(&name.as_str()))
    {
        return value_error("native_guard_store_invalid");
    }
    let mut fields = decision.clone();
    fields.insert("now".to_owned(), Value::from(resolved_at));
    for name in DECISION_RESERVED.into_iter().skip(1) {
        if let Some(value) = args.raw(name) {
            fields.insert(name.to_owned(), value.clone());
        }
    }
    let written = upsert_policy(connection, &Args(&fields))?;
    Ok(written
        .get("next_control_state")
        .cloned()
        .unwrap_or(Value::Null))
}

/// `_covered_pending_request_ids_locked`: the pending requests of the same
/// harness that this grant answers, minus any that cannot be resolved at all.
/// An exact grant covers only the request that asked for it.
fn covered_request_ids(
    connection: &Connection,
    guard_home: &str,
    request_id: &str,
    source: &Value,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Vec<String>> {
    let target = args.str("grant_target")?;
    if target == "exact" {
        return Ok(Vec::new());
    }
    let server = args.str("grant_server_identity_hash")?;
    let category = args.str("grant_category")?;
    let whole_server = target == "server";
    let harness = source["harness"].as_str().unwrap_or_default();
    let rows = query_all(
        connection,
        &format!(
            "select {COLUMNS} from approval_requests where status = 'pending' and harness = ? {ORDER}"
        ),
        &[Value::from(harness)],
    )?;
    let mut covered = Vec::new();
    for row in &rows {
        let projection = project(row, guard_home)?;
        let item = Value::Object(
            payloads(
                vec![(row, projection)],
                None,
                owner.map(|owner| (connection, owner)),
            )?
            .remove(0),
        );
        let Some(candidate_id) = item["request_id"].as_str() else {
            continue;
        };
        if candidate_id == request_id
            || !covers(&item, server, category, whole_server)
            || block_reason(&item).is_some()
        {
            continue;
        }
        covered.push(candidate_id.to_owned());
    }
    Ok(covered)
}

/// `temporary_mcp_grant_covers_request`: a broad grant answers a pending
/// request when that request is itself routine for the same server, and for
/// the same category unless the grant covers the whole server.
fn covers(item: &Value, server: &str, category: &str, whole_server: bool) -> bool {
    let Some((candidate_server, candidate_category)) = eligibility(&item["browser_intent"]) else {
        return false;
    };
    candidate_server == server && (whole_server || candidate_category == category)
}

/// `eligibility_from_browser_intent`: the server a stored browser intent names
/// and the routine category it is eligible for, or none when the call carries
/// risk beyond that one category.
fn eligibility(intent: &Value) -> Option<(&str, &'static str)> {
    let text = |name: &str| -> Option<&str> {
        let value = python_strip(intent.get(name)?.as_str()?);
        (!value.is_empty()).then_some(value)
    };
    let server = text("mcp_server_identity_hash")?;
    text("mcp_server_name")?;
    let category = category_for(text("intent")?)?;
    // The stored risk categories are compared as they were written: only the
    // fields above are stripped on the way in.
    let risks: Vec<&str> = intent
        .get("risk_categories")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !risks.contains(&category)
        || risks
            .iter()
            .any(|risk| *risk != category && *risk != INFORMATIONAL_CATEGORY)
    {
        return None;
    }
    Some((server, category))
}

/// `bulk_resolve_approval_requests`: the covered requests, resolved the way
/// the grant resolves the one that asked for it. Still-pending is part of the
/// statement, so a request resolved between the sweep and here is left alone.
fn resolve_covered(
    connection: &Connection,
    covered: &[String],
    resolution: &[Value; 4],
) -> StoreResult<()> {
    if covered.is_empty() {
        return Ok(());
    }
    let placeholders = vec!["?"; covered.len()].join(",");
    let mut params = resolution.to_vec();
    params.extend(covered.iter().map(|id| Value::from(id.as_str())));
    exec(
        connection,
        &format!(
            "update approval_requests \
             set status = 'resolved', resolution_action = ?, resolution_scope = ?, \
                 reason = ?, resolved_at = ? \
             where request_id in ({placeholders}) and status = 'pending'"
        ),
        &params,
    )?;
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "guard_store_temporary_mcp_tests.rs"]
mod tests;
