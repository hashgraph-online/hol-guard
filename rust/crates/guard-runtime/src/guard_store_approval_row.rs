//! The column values of one approval queue row: `_update_request` and
//! `_insert_request` of `store_approval_writes.py`, with Python's exact SQL
//! and parameter order.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_approval_request::{
    json_text, optional_json, rewrite_approval_url, rewrite_review_command, stored_correlation,
    ApprovalRequest,
};
use crate::guard_store_db::{exec, placeholders, query_one, StoreError, StoreResult};

/// The canonical surfaces and queue identity of the request being written.
pub(crate) struct Derived {
    pub(crate) policy_action: Value,
    pub(crate) decision: Value,
    pub(crate) envelope: Value,
    pub(crate) identity_key: String,
    pub(crate) action_identity: String,
    pub(crate) queue_group_id: String,
}

fn optional_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, Value::from)
}

/// `_update_request`.
pub(crate) fn update(
    connection: &Connection,
    request: &ApprovalRequest,
    derived: &Derived,
    request_id: &str,
    oauth_source: &str,
    now: &str,
) -> StoreResult<()> {
    let stored = query_one(
        connection,
        "select continuation_snapshot_json from approval_requests \
         where request_id = ? and oauth_source = ?",
        &[Value::from(request_id), Value::from(oauth_source)],
    )?;
    let stored_snapshot = stored
        .as_ref()
        .and_then(|row| row.get("continuation_snapshot_json"))
        .and_then(Value::as_str);
    let correlation = stored_correlation(request_id, stored_snapshot)
        .ok_or_else(|| StoreError::Value("local_request_id is required".to_owned()))?;
    let fallback = request
        .fallback_cli_command
        .as_deref()
        .filter(|command| !command.is_empty())
        .map(|command| rewrite_review_command(command, request_id));
    let watch_only = request.watch_only();
    let params = vec![
        Value::from(request.harness.as_str()),
        Value::from(request.artifact_name.as_str()),
        Value::from(request.artifact_type.as_str()),
        Value::from(request.artifact_hash.as_str()),
        optional_text(request.publisher.as_deref()),
        derived.policy_action.clone(),
        Value::from(request.recommended_scope.as_str()),
        request.changed_fields_json()?,
        Value::from(request.source_scope.as_str()),
        Value::from(request.config_path.as_str()),
        optional_text(request.workspace.as_deref()),
        optional_text(request.launch_target.as_deref()),
        Value::from(derived.identity_key.as_str()),
        Value::from(derived.action_identity.as_str()),
        Value::from(derived.queue_group_id.as_str()),
        Value::from(now),
        optional_text(request.transport.as_deref()),
        optional_text(request.risk_summary.as_deref()),
        request.risk_signals_json()?,
        optional_text(request.artifact_label.as_deref()),
        optional_text(request.source_label.as_deref()),
        optional_text(request.trigger_summary.as_deref()),
        optional_text(request.why_now.as_deref()),
        optional_text(request.launch_summary.as_deref()),
        optional_text(request.risk_headline.as_deref()),
        optional_json(&derived.envelope)?,
        json_text(&derived.decision)?,
        optional_text(fallback.as_deref()),
        request.scanner_evidence_json()?,
        Value::from(watch_only),
        request.browser_intent_json()?,
        Value::from(rewrite_review_command(&request.review_command, request_id)),
        Value::from(rewrite_approval_url(&request.approval_url, request_id)),
        optional_text(request.raw_command_text.as_deref()),
        optional_text(request.guard_version.as_deref()),
        request.continuation_snapshot_json(Some(correlation))?,
        request.extension_allow_hint_json()?,
        request.first_seen_version(),
        request.last_seen_version(),
        Value::from(request_id),
        Value::from(oauth_source),
    ];
    exec(
        connection,
        "update approval_requests \
         set harness = ?, artifact_name = ?, artifact_type = ?, artifact_hash = ?, publisher = ?, \
         policy_action = ?, recommended_scope = ?, changed_fields_json = ?, source_scope = ?, \
         config_path = ?, workspace = ?, launch_target = ?, normalized_identity_key = ?, \
         action_identity = ?, queue_group_id = ?, \
         dedupe_count = coalesce(dedupe_count, 1) + 1, last_seen_at = ?, transport = ?, \
         risk_summary = ?, risk_signals_json = ?, artifact_label = ?, source_label = ?, \
         trigger_summary = ?, why_now = ?, launch_summary = ?, risk_headline = ?, \
         action_envelope_json = ?, decision_v2_json = ?, fallback_cli_command = ?, \
         scanner_evidence_json = ?, \
         watch_only_observation = case when watch_only_observation = 1 and ? = 1 then 1 else 0 end, \
         browser_intent_json = ?, review_command = ?, approval_url = ?, raw_command_text = ?, \
         guard_version = ?, continuation_snapshot_json = ?, extension_allow_hint_json = ?, \
         first_seen_guard_version = coalesce(first_seen_guard_version, ?), \
         last_seen_guard_version = ? \
         where request_id = ? and oauth_source = ?",
        &params,
    )?;
    Ok(())
}

/// `_insert_request`.
pub(crate) fn insert(
    connection: &Connection,
    request: &ApprovalRequest,
    derived: &Derived,
    oauth_source: &str,
    now: &str,
) -> StoreResult<()> {
    let last_seen = request
        .last_seen_at
        .as_deref()
        .filter(|seen| !seen.is_empty())
        .unwrap_or(now);
    let params = vec![
        Value::from(request.request_id.as_str()),
        Value::from(request.harness.as_str()),
        Value::from(request.artifact_id.as_str()),
        Value::from(request.artifact_name.as_str()),
        Value::from(request.artifact_type.as_str()),
        Value::from(request.artifact_hash.as_str()),
        optional_text(request.publisher.as_deref()),
        derived.policy_action.clone(),
        Value::from(request.recommended_scope.as_str()),
        request.changed_fields_json()?,
        Value::from(request.source_scope.as_str()),
        Value::from(oauth_source),
        Value::from(request.config_path.as_str()),
        optional_text(request.workspace.as_deref()),
        optional_text(request.launch_target.as_deref()),
        Value::from(derived.identity_key.as_str()),
        Value::from(derived.action_identity.as_str()),
        Value::from(derived.queue_group_id.as_str()),
        Value::from(request.dedupe_count.max(1)),
        Value::from(last_seen),
        optional_text(request.transport.as_deref()),
        optional_text(request.risk_summary.as_deref()),
        request.risk_signals_json()?,
        optional_text(request.artifact_label.as_deref()),
        optional_text(request.source_label.as_deref()),
        optional_text(request.trigger_summary.as_deref()),
        optional_text(request.why_now.as_deref()),
        optional_text(request.launch_summary.as_deref()),
        optional_text(request.risk_headline.as_deref()),
        optional_json(&derived.envelope)?,
        json_text(&derived.decision)?,
        optional_text(request.fallback_cli_command.as_deref()),
        request.scanner_evidence_json()?,
        request.browser_intent_json()?,
        Value::from(request.review_command.as_str()),
        Value::from(request.approval_url.as_str()),
        Value::from("pending"),
        Value::Null,
        Value::Null,
        Value::Null,
        Value::from(now),
        Value::Null,
        optional_text(request.raw_command_text.as_deref()),
        optional_text(request.guard_version.as_deref()),
        request.first_seen_version(),
        request.last_seen_version(),
        Value::from(request.watch_only()),
        request.continuation_snapshot_json(None)?,
        request.extension_allow_hint_json()?,
    ];
    exec(
        connection,
        &format!(
            "insert into approval_requests (\
             request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, \
             publisher, policy_action, recommended_scope, changed_fields_json, source_scope, \
             oauth_source, config_path, workspace, launch_target, normalized_identity_key, \
             action_identity, queue_group_id, dedupe_count, last_seen_at, transport, \
             risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, \
             why_now, launch_summary, risk_headline, action_envelope_json, decision_v2_json, \
             fallback_cli_command, scanner_evidence_json, browser_intent_json, review_command, \
             approval_url, status, resolution_action, resolution_scope, reason, created_at, \
             resolved_at, raw_command_text, guard_version, first_seen_guard_version, \
             last_seen_guard_version, watch_only_observation, continuation_snapshot_json, \
             extension_allow_hint_json) values ({})",
            placeholders(params.len())
        ),
        &params,
    )?;
    Ok(())
}
