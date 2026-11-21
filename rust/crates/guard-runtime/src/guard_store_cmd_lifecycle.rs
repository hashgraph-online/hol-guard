//! Lifecycle updates and persistence-health bookkeeping for command activity.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_cmd_rollups::record_transition;
use crate::guard_store_cmd_wire::{
    column_values, optional_handle, rows_equal, text_of, Evidence, Handle,
};
use crate::guard_store_db::{
    exec, query_all, query_one, runtime_error, text, value_error, Row, StoreError, StoreResult,
};

const MAX_COUNTER: i64 = i64::MAX;
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// Clear only the active error class recovered by one successful operation.
pub(crate) fn recover(connection: &Connection, domain: &str) -> StoreResult<()> {
    let column = match domain {
        "command" => "command_error_active",
        "shadow" => "shadow_error_active",
        "maintenance" => "maintenance_error_active",
        _ => return value_error("invalid persistence error domain"),
    };
    exec(
        connection,
        &format!("update command_activity_health_active set {column} = 0 where singleton = 1"),
        &[],
    )?;
    Ok(())
}

fn select_by_request_correlation(
    connection: &Connection,
    handle: &Handle,
) -> StoreResult<Option<Row>> {
    query_one(
        connection,
        "select activity.* from command_activity as activity \
         join command_activity_correlations as correlation \
           on correlation.activity_id = activity.activity_id \
         where correlation.kind = 'request' and correlation.harness = ? \
           and correlation.key_id = ? and correlation.digest = ?",
        &[
            Value::from(handle.harness.as_str()),
            Value::from(handle.key_id.as_str()),
            Value::from(handle.digest.as_str()),
        ],
    )
}

/// The persisted activity with its `request_correlation` and
/// `session_correlation` handles attached.
fn activity_with_handles(connection: &Connection, mut row: Row) -> StoreResult<Row> {
    let handles = query_all(
        connection,
        "select kind, harness, key_id, digest from command_activity_correlations \
         where activity_id = ?",
        &[Value::from(text(&row, "activity_id"))],
    )?;
    for key in ["request", "session"] {
        let handle = handles
            .iter()
            .rev()
            .find(|item| text(item, "kind") == key)
            .map(|item| Handle::from_row(item).map(|handle| handle.to_value()))
            .transpose()?;
        row.insert(format!("{key}_correlation"), handle.unwrap_or(Value::Null));
    }
    Ok(row)
}

fn request_handle(args: &Args) -> StoreResult<Handle> {
    optional_handle(args.0, "correlation")?.ok_or(INVALID)
}

pub(crate) fn activity_by_correlation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let handle = request_handle(args)?;
    Ok(match select_by_request_correlation(connection, &handle)? {
        Some(row) => Value::Object(activity_with_handles(connection, row)?),
        None => Value::Null,
    })
}

fn pre_replay_fields() -> [&'static str; 14] {
    [
        "harness",
        "policy_action",
        "decision_reason_code",
        "controlling_rule_id",
        "parse_confidence",
        "uncertainty_class",
        "match_count",
        "prompted",
        "approval_reuse_status",
        "request_correlation",
        "session_correlation",
        "receipt_link_status",
        "evaluation_latency_bucket",
        "schema_version",
    ]
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

/// Normalize a wire activity so booleans compare as stored integers.
fn wire_activity(activity: &Map<String, Value>) -> Map<String, Value> {
    let mut out = activity.clone();
    for key in ["request_correlation", "session_correlation"] {
        out.entry(key.to_owned()).or_insert(Value::Null);
    }
    if let Some(Value::Bool(flag)) = out.get("prompted") {
        let flag = i64::from(*flag);
        out.insert("prompted".to_owned(), Value::from(flag));
    }
    out
}

pub(crate) fn is_exact_pre_replay(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let evidence = Evidence::from_args(args)?;
    let Some(handle) = optional_handle(evidence.activity, "request_correlation")? else {
        return Ok(json!(false));
    };
    if handle.kind != "request" {
        return Err(INVALID);
    }
    let Some(row) = select_by_request_correlation(connection, &handle)? else {
        return Ok(json!(false));
    };
    let previous = activity_with_handles(connection, row)?;
    let activity_id = text(&previous, "activity_id").to_owned();
    let columns = [
        "ordinal",
        "extension_id",
        "extension_version",
        "rule_id",
        "rule_version",
        "match_class",
        "severity",
        "default_floor",
        "safe_variant_id",
        "schema_version",
    ];
    let id = [Value::from(activity_id)];
    let matches = query_all(
        connection,
        "select ordinal, extension_id, extension_version, rule_id, rule_version, match_class, \
         severity, default_floor, safe_variant_id, schema_version \
         from command_activity_matches where activity_id = ? order by ordinal",
        &id,
    )?;
    let effects = query_all(
        connection,
        "select ordinal, effect_class from command_activity_match_effects \
         where activity_id = ? order by ordinal, effect_class",
        &id,
    )?;
    let expected_matches = evidence
        .matches
        .iter()
        .map(|item| column_values(item, &columns))
        .collect::<StoreResult<Vec<_>>>()?;
    let expected_effects = evidence
        .effect_values()?
        .into_iter()
        .map(|row| row[1..].to_vec())
        .collect::<Vec<_>>();
    let current = wire_activity(evidence.activity);
    let same_activity = pre_replay_fields()
        .iter()
        .all(|key| field(&previous, key) == field(&current, key));
    if same_activity
        && rows_equal(&matches, &columns, &expected_matches)
        && rows_equal(&effects, &["ordinal", "effect_class"], &expected_effects)
    {
        Ok(json!(true))
    } else {
        value_error("conflicting command activity replay")
    }
}

const IMMUTABLE: [&str; 17] = [
    "activity_id",
    "occurred_at",
    "harness",
    "policy_action",
    "decision_reason_code",
    "controlling_rule_id",
    "parse_confidence",
    "uncertainty_class",
    "match_count",
    "prompted",
    "approval_reuse_status",
    "request_correlation",
    "session_correlation",
    "receipt_link_status",
    "receipt_id",
    "evaluation_latency_bucket",
    "schema_version",
];

fn validate_transition(previous: &Row, current: &Map<String, Value>) -> StoreResult<()> {
    if IMMUTABLE
        .iter()
        .any(|key| field(previous, key) != field(current, key))
    {
        return value_error(
            "activity transitions cannot change decision, identity, proof, or match facts",
        );
    }
    let (before, after) = (
        text(previous, "execution_status"),
        text_of(current, "execution_status")?,
    );
    if before == after {
        let changed = ["hook_phase", "proof_level", "persistence_latency_bucket"]
            .iter()
            .any(|key| field(previous, key) != field(current, key));
        if changed {
            return value_error("idempotent activity replay cannot change persisted fields");
        }
        return Ok(());
    }
    let allowed: &[&str] = match before {
        "attempted" => &["prevented", "allowed_unconfirmed"],
        "allowed_unconfirmed" => &["confirmed_success", "confirmed_failure"],
        _ => &[],
    };
    if allowed.contains(&after) {
        Ok(())
    } else {
        value_error("invalid or conflicting command activity lifecycle transition")
    }
}

/// Atomically advance one correlated activity; `false` for an exact replay.
pub(crate) fn transition(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let current = wire_activity(args.object("current")?);
    let handle = optional_handle(&current, "request_correlation")?.ok_or(INVALID)?;
    let Some(row) = select_by_request_correlation(connection, &handle)? else {
        return value_error("command activity correlation does not identify a pre-hook record");
    };
    let previous = activity_with_handles(connection, row)?;
    if text(&previous, "activity_id") != text_of(&current, "activity_id")? {
        return value_error("command activity correlation conflicts with activity identity");
    }
    validate_transition(&previous, &current)?;
    let columns = [
        "hook_phase",
        "execution_status",
        "proof_level",
        "persistence_latency_bucket",
    ];
    if columns
        .iter()
        .all(|key| field(&previous, key) == field(&current, key))
    {
        return Ok(json!(false));
    }
    let mut params = column_values(&current, &columns)?;
    params.push(Value::from(text(&previous, "activity_id")));
    for key in columns {
        params.push(field(&previous, key).clone());
    }
    let changed = exec(
        connection,
        "update command_activity \
         set hook_phase = ?, execution_status = ?, proof_level = ?, persistence_latency_bucket = ? \
         where activity_id = ? and hook_phase = ? and execution_status = ? \
           and proof_level = ? and persistence_latency_bucket = ?",
        &params,
    )?;
    if changed != 1 {
        return runtime_error("command activity changed during lifecycle transition");
    }
    record_transition(connection, &previous, &current)?;
    recover(connection, "command")?;
    Ok(json!(true))
}

fn error_domain(code: &str) -> &'static str {
    match code {
        "maintenance_failed" => "maintenance_error_active",
        "shadow_evaluation_failed" => "shadow_error_active",
        _ => "command_error_active",
    }
}

pub(crate) fn persistence_failure(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let code = args.str("error_code")?;
    exec(
        connection,
        "update command_activity_health \
         set dropped_event_count = min(dropped_event_count + 1, ?), \
             persistence_error_count = min(persistence_error_count + 1, ?), \
             last_error_code = ?, last_error_at = ? where singleton = 1",
        &[
            Value::from(MAX_COUNTER),
            Value::from(MAX_COUNTER),
            Value::from(code),
            Value::from(args.str("occurred_at")?),
        ],
    )?;
    exec(
        connection,
        &format!(
            "update command_activity_health_active set {} = 1 where singleton = 1",
            error_domain(code)
        ),
        &[],
    )?;
    Ok(Value::Null)
}

pub(crate) fn observation_conflict(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "update command_activity_health \
         set dropped_event_count = min(dropped_event_count + 1, ?), \
             last_error_code = 'post_result_conflict', last_error_at = ? where singleton = 1",
        &[
            Value::from(MAX_COUNTER),
            Value::from(args.str("occurred_at")?),
        ],
    )?;
    Ok(Value::Null)
}
