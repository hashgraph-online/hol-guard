//! Command-activity API reads and feedback: bounded activity pages, windowed
//! analytics with feedback and health, feedback upserts and invalidation
//! pages. Python validates the query objects and sends column-shaped filters;
//! it never recomputes a persisted fact.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    int, placeholders, query_all, query_one, text, Row, StoreError, StoreResult,
};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const MAX_PAGE: i64 = 100;
const DIMENSIONS: [&str; 8] = [
    "harness",
    "extension",
    "rule",
    "disposition",
    "execution_status",
    "prompt_status",
    "proof_level",
    "latency",
];

/// `str(value)` for a non-null cell; SQL NULL stays JSON null.
fn as_text(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(text)) => Value::String(text.clone()),
        Some(other) => Value::String(other.to_string()),
    }
}

fn filter_text<'a>(filters: &'a Map<String, Value>, key: &str) -> StoreResult<Option<&'a str>> {
    match filters.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(INVALID),
    }
}

fn page_cursor(args: &Args) -> StoreResult<Option<(String, String)>> {
    let Some(value) = args.raw("cursor") else {
        return Ok(None);
    };
    match value.as_array().map(Vec::as_slice) {
        Some([Value::String(occurred_at), Value::String(activity_id)]) => {
            Ok(Some((occurred_at.clone(), activity_id.clone())))
        }
        _ => Err(INVALID),
    }
}

fn match_subquery(column: &str) -> String {
    format!(
        "activity.activity_id in (select match.activity_id from command_activity_matches \
         as match where match.{column} = ?)"
    )
}

pub(crate) fn page_query(
    filters: &Map<String, Value>,
    cursor: Option<&(String, String)>,
    limit: i64,
) -> StoreResult<(String, Vec<Value>)> {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();
    for (column, key) in [
        ("activity.harness", "harness"),
        ("activity.execution_status", "execution_status"),
        ("activity.proof_level", "proof_level"),
        ("activity.approval_reuse_status", "approval_reuse_status"),
    ] {
        if let Some(value) = filter_text(filters, key)? {
            clauses.push(format!("{column} = ?"));
            params.push(Value::from(value));
        }
    }
    match filters.get("prompted") {
        None | Some(Value::Null) => {}
        Some(Value::Bool(flag)) => {
            clauses.push("activity.prompted = ?".to_owned());
            params.push(Value::from(i64::from(*flag)));
        }
        Some(_) => return Err(INVALID),
    }
    if let Some(from) = filter_text(filters, "occurred_from")? {
        clauses.push("activity.occurred_at >= ?".to_owned());
        params.push(Value::from(from));
    }
    if let Some(until) = filter_text(filters, "occurred_until")? {
        let inclusive = filters.get("until_inclusive") == Some(&Value::Bool(true));
        clauses.push(format!(
            "activity.occurred_at {} ?",
            if inclusive { "<=" } else { "<" }
        ));
        params.push(Value::from(until));
    }
    for (column, key) in [("extension_id", "extension_id"), ("rule_id", "rule_id")] {
        if let Some(value) = filter_text(filters, key)? {
            clauses.push(match_subquery(column));
            params.push(Value::from(value));
        }
    }
    if let Some((occurred_at, activity_id)) = cursor {
        clauses.push(
            "(activity.occurred_at < ? or (activity.occurred_at = ? and activity.activity_id < ?))"
                .to_owned(),
        );
        params.extend([
            Value::from(occurred_at.as_str()),
            Value::from(occurred_at.as_str()),
            Value::from(activity_id.as_str()),
        ]);
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" where {}", clauses.join(" and "))
    };
    params.push(Value::from(limit + 1));
    Ok((
        format!(
            "select activity.*, feedback.label as feedback_label, \
             invocation.invocation_preview as invocation_preview \
             from command_activity as activity \
             left join command_activity_feedback as feedback using (activity_id) \
             left join command_activity_invocation as invocation using (activity_id)\
             {where_clause} order by activity.occurred_at desc, activity.activity_id desc limit ?"
        ),
        params,
    ))
}

fn match_payload(row: &Row) -> Map<String, Value> {
    let mut item = Map::new();
    item.insert("ordinal".to_owned(), Value::from(int(row, "ordinal")));
    for key in [
        "extension_id",
        "extension_version",
        "rule_id",
        "rule_version",
        "match_class",
        "severity",
        "default_floor",
        "safe_variant_id",
        "schema_version",
    ] {
        item.insert(key.to_owned(), as_text(row.get(key)));
    }
    item.insert("effect_classes".to_owned(), json!([]));
    item
}

type MatchGroups = Vec<(String, Vec<Map<String, Value>>)>;

/// Match items per activity, in `(activity_id, ordinal)` order with their
/// sorted effect classes.
fn matches_by_activity(connection: &Connection, ids: &[&str]) -> StoreResult<MatchGroups> {
    let params: Vec<Value> = ids.iter().map(|id| Value::from(*id)).collect();
    let rows = query_all(
        connection,
        &format!(
            "select matches.*, effects.effect_class from command_activity_matches as matches \
             left join command_activity_match_effects as effects \
               on effects.activity_id = matches.activity_id and effects.ordinal = matches.ordinal \
             where matches.activity_id in ({}) \
             order by matches.activity_id, matches.ordinal, effects.effect_class",
            placeholders(ids.len())
        ),
        &params,
    )?;
    let mut grouped: MatchGroups = Vec::new();
    let mut last_key: Option<(String, i64)> = None;
    for row in &rows {
        let key = (text(row, "activity_id").to_owned(), int(row, "ordinal"));
        if last_key.as_ref() != Some(&key) {
            if grouped.last().map(|(id, _)| id.as_str()) != Some(key.0.as_str()) {
                grouped.push((key.0.clone(), Vec::new()));
            }
            grouped.last_mut().unwrap().1.push(match_payload(row));
            last_key = Some(key);
        }
        if let Some(effect) = row.get("effect_class").filter(|value| !value.is_null()) {
            let item = grouped.last_mut().unwrap().1.last_mut().unwrap();
            if let Some(Value::Array(effects)) = item.get_mut("effect_classes") {
                effects.push(as_text(Some(effect)));
            }
        }
    }
    Ok(grouped)
}

fn activity_payload(row: &Row, matches: Vec<Map<String, Value>>) -> Value {
    let mut item = Map::new();
    for key in [
        "activity_id",
        "occurred_at",
        "harness",
        "hook_phase",
        "execution_status",
        "proof_level",
        "policy_action",
        "decision_reason_code",
        "controlling_rule_id",
        "parse_confidence",
        "uncertainty_class",
        "approval_reuse_status",
        "receipt_link_status",
        "receipt_id",
        "evaluation_latency_bucket",
        "persistence_latency_bucket",
        "feedback_label",
        "schema_version",
        "invocation_preview",
    ] {
        item.insert(key.to_owned(), as_text(row.get(key)));
    }
    item.insert(
        "match_count".to_owned(),
        Value::from(int(row, "match_count")),
    );
    item.insert(
        "prompted".to_owned(),
        Value::Bool(int(row, "prompted") != 0),
    );
    item.insert(
        "matches".to_owned(),
        Value::Array(matches.into_iter().map(Value::Object).collect()),
    );
    Value::Object(item)
}

pub(crate) fn list_page(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let filters = args.object("filters")?;
    let limit = args.int("limit")?;
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(INVALID);
    }
    let cursor = page_cursor(args)?;
    let (sql, params) = page_query(filters, cursor.as_ref(), limit)?;
    let rows = query_all(connection, &sql, &params)?;
    let take = rows.len().min(limit as usize);
    let page = &rows[..take];
    let ids: Vec<&str> = page.iter().map(|row| text(row, "activity_id")).collect();
    let mut grouped = if ids.is_empty() {
        Vec::new()
    } else {
        matches_by_activity(connection, &ids)?
    };
    let items: Vec<Value> = page
        .iter()
        .map(|row| {
            let id = text(row, "activity_id");
            let matches = grouped
                .iter()
                .position(|(key, _)| key == id)
                .map(|index| grouped.swap_remove(index).1)
                .unwrap_or_default();
            activity_payload(row, matches)
        })
        .collect();
    let next_marker = match page.last() {
        Some(last) if rows.len() > take => {
            json!([
                as_text(last.get("occurred_at")),
                as_text(last.get("activity_id"))
            ])
        }
        _ => Value::Null,
    };
    Ok(json!({ "items": items, "next_marker": next_marker }))
}

fn day_counts(rows: &[Row], count_key: &str) -> Vec<Value> {
    rows.iter()
        .map(|row| json!({ "day": as_text(row.get("day")), "count": int(row, count_key) }))
        .collect()
}

fn trend(connection: &Connection, args: &Args, start: &str, end: &str) -> StoreResult<Vec<Value>> {
    let dimension = args.opt_str("dimension")?;
    let rows = match dimension {
        None => query_all(
            connection,
            "select day, total as count from command_activity_daily_totals \
             where day between ? and ? order by day",
            &[Value::from(start), Value::from(end)],
        )?,
        Some(dimension) => query_all(
            connection,
            "select day, count from command_activity_daily_rollups \
             where day between ? and ? and dimension = ? and dimension_value = ? order by day",
            &[
                Value::from(start),
                Value::from(end),
                Value::from(dimension),
                args.raw("dimension_value").cloned().unwrap_or(Value::Null),
            ],
        )?,
    };
    Ok(day_counts(&rows, "count"))
}

fn top_dimension(
    connection: &Connection,
    dimension: &str,
    start: &str,
    end: &str,
    limit: i64,
) -> StoreResult<Vec<Value>> {
    let rows = query_all(
        connection,
        "select dimension_value, sum(count) as total from command_activity_daily_rollups \
         where day between ? and ? and dimension = ? \
         group by dimension_value order by total desc, dimension_value limit ?",
        &[
            Value::from(start),
            Value::from(end),
            Value::from(dimension),
            Value::from(limit),
        ],
    )?;
    Ok(rows
        .iter()
        .map(|row| json!({ "value": as_text(row.get("dimension_value")), "count": int(row, "total") }))
        .collect())
}

fn feedback_counts(connection: &Connection, args: &Args) -> StoreResult<Vec<Value>> {
    let mut clauses = vec![
        "activity.occurred_at >= ?".to_owned(),
        "activity.occurred_at < ?".to_owned(),
    ];
    let mut params = vec![
        Value::from(args.str("feedback_from")?),
        Value::from(args.str("feedback_before")?),
    ];
    let value = args.raw("dimension_value").cloned().unwrap_or(Value::Null);
    match args.opt_str("dimension")? {
        Some("harness") => {
            clauses.push("activity.harness = ?".to_owned());
            params.push(value);
        }
        Some(kind @ ("extension" | "rule")) => {
            let column = if kind == "extension" {
                "extension_id"
            } else {
                "rule_id"
            };
            clauses.push(match_subquery(column));
            params.push(value);
        }
        _ => {}
    }
    let rows = query_all(
        connection,
        &format!(
            "select feedback.label, count(*) as total from command_activity_feedback as feedback \
             join command_activity as activity using (activity_id) \
             where {} group by feedback.label order by feedback.label",
            clauses.join(" and ")
        ),
        &params,
    )?;
    Ok(rows
        .iter()
        .map(|row| json!({ "label": as_text(row.get("label")), "count": int(row, "total") }))
        .collect())
}

fn health_payload(connection: &Connection) -> StoreResult<Value> {
    let Some(row) = query_one(
        connection,
        "select * from command_activity_health where singleton = 1",
        &[],
    )?
    else {
        return Ok(json!({ "status": "degraded", "dropped_events": 0, "persistence_errors": 0 }));
    };
    let active = query_one(
        connection,
        "select * from command_activity_health_active where singleton = 1",
        &[],
    )?;
    let degraded = active.as_ref().is_none_or(|active| {
        [
            "command_error_active",
            "shadow_error_active",
            "maintenance_error_active",
        ]
        .iter()
        .any(|column| int(active, column) != 0)
    });
    Ok(json!({
        "status": if degraded { "degraded" } else { "healthy" },
        "dropped_events": int(&row, "dropped_event_count"),
        "persistence_errors": int(&row, "persistence_error_count"),
        "last_error_class": as_text(row.get("last_error_code")),
        "last_error_at": as_text(row.get("last_error_at")),
    }))
}

pub(crate) fn analytics(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (start, end) = (args.str("start")?, args.str("end")?);
    let top_limit = args.int("top_limit")?;
    let trend = trend(connection, args, start, end)?;
    let mut dimensions = Map::new();
    for dimension in DIMENSIONS {
        dimensions.insert(
            dimension.to_owned(),
            Value::Array(top_dimension(connection, dimension, start, end, top_limit)?),
        );
    }
    let feedback = feedback_counts(connection, args)?;
    let health = health_payload(connection)?;
    let total: i64 = trend
        .iter()
        .map(|item| item["count"].as_i64().unwrap_or(0))
        .sum();
    Ok(json!({
        "window": { "from": start, "through": end, "days": args.int("days")? },
        "scope": {
            "dimension": as_text(args.raw("dimension")),
            "dimension_value": as_text(args.raw("dimension_value")),
        },
        "commands_checked": total,
        "trend": trend,
        "dimensions": dimensions,
        "dimension_breakdowns_scope": "global",
        "feedback": feedback,
        "health": health,
    }))
}
