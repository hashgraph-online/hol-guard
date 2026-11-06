//! `load_receipt_analytics`: dashboard activity, trend and top-N views over the
//! persisted receipt rollups.

use std::collections::HashMap;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_db::{int, is_null, query_all, query_one, runtime_error, text, StoreResult};
use crate::guard_store_json::{civil_date, epoch_days};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn day_key(days: i64) -> String {
    let (year, month, day) = civil_date(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn label(days: i64) -> String {
    let (_, month, day) = civil_date(days);
    format!(
        "{} {day}",
        MONTHS[usize::try_from(month - 1).unwrap_or(0) % 12]
    )
}

fn optional_text(row: Option<&crate::guard_store_db::Row>, name: &str) -> Value {
    match row {
        Some(row) if !is_null(row, name) && !text(row, name).is_empty() => {
            Value::from(text(row, name))
        }
        _ => Value::Null,
    }
}

pub(crate) fn load(
    connection: &Connection,
    now: &str,
    activity_days: i64,
    trend_days: i64,
    top_limit: i64,
) -> StoreResult<Value> {
    let Some(today) = epoch_days(now) else {
        return runtime_error("native_guard_store_invalid_now");
    };
    let activity_start = today - (activity_days - 1);
    let trend_start = today - (trend_days - 1);
    let activity_start_key = day_key(activity_start);
    let trend_start_key = day_key(trend_start);

    let totals = query_one(
        connection,
        "select total, allowed, blocked, reviewed, first_activity_at, last_activity_at \
         from receipt_aggregate_totals where totals_key = 'global'",
        &[],
    )?;
    let daily = query_all(
        connection,
        "select day_key, total, allowed, blocked, reviewed from receipt_daily_rollups \
         where day_key >= ? order by day_key asc",
        &[Value::from(activity_start_key)],
    )?;
    let top = |sql: &str| query_all(connection, sql, &[Value::from(top_limit)]);
    let harnesses = top(
        "select harness, total, allowed, blocked, reviewed from receipt_harness_rollups \
         order by total desc limit ?",
    )?;
    let artifacts = top(
        "select artifact_key, total, allowed, blocked, reviewed from receipt_artifact_rollups \
         order by total desc limit ?",
    )?;

    let field = |name: &str| totals.as_ref().map_or(0, |row| int(row, name));
    let daily_totals: HashMap<&str, i64> = daily
        .iter()
        .map(|row| (text(row, "day_key"), int(row, "total")))
        .collect();
    let trend_counts: HashMap<&str, [i64; 3]> = daily
        .iter()
        .filter(|row| text(row, "day_key") >= trend_start_key.as_str())
        .map(|row| {
            (
                text(row, "day_key"),
                [
                    int(row, "allowed"),
                    int(row, "blocked"),
                    int(row, "reviewed"),
                ],
            )
        })
        .collect();

    let activity: Vec<(String, i64)> = (0..activity_days)
        .map(|offset| {
            let key = day_key(activity_start + offset);
            let total = daily_totals.get(key.as_str()).copied().unwrap_or(0);
            (key, total)
        })
        .collect();
    let trend: Vec<Value> = (0..trend_days)
        .map(|offset| {
            let day = trend_start + offset;
            let key = day_key(day);
            let [allowed, blocked, reviewed] =
                trend_counts.get(key.as_str()).copied().unwrap_or([0, 0, 0]);
            json!({
                "date_key": key, "label": label(day),
                "allowed": allowed, "blocked": blocked, "reviewed": reviewed,
            })
        })
        .collect();

    let mut streak_entries: Vec<i64> = activity.iter().rev().map(|(_, total)| *total).collect();
    if streak_entries.first() == Some(&0) {
        streak_entries.remove(0);
    }
    let streak = streak_entries
        .iter()
        .take_while(|total| **total > 0)
        .count();
    let peak = activity.iter().map(|(_, total)| *total).max().unwrap_or(0);

    let ranked = |rows: &[crate::guard_store_db::Row], key: &str, name: &str| -> Vec<Value> {
        rows.iter()
            .map(|row| {
                json!({
                    name: text(row, key), "total": int(row, "total"),
                    "allowed": int(row, "allowed"), "blocked": int(row, "blocked"),
                })
            })
            .collect()
    };
    Ok(json!({
        "total": field("total"), "allowed": field("allowed"),
        "blocked": field("blocked"), "reviewed": field("reviewed"),
        "first_activity_at": optional_text(totals.as_ref(), "first_activity_at"),
        "last_activity_at": optional_text(totals.as_ref(), "last_activity_at"),
        "active_day_streak": streak, "peak_day_total": peak,
        "daily_activity": activity.iter()
            .map(|(key, total)| json!({"date_key": key, "total": total}))
            .collect::<Vec<_>>(),
        "trend_buckets": trend,
        "by_harness": ranked(&harnesses, "harness", "harness"),
        "top_artifacts": ranked(&artifacts, "artifact_key", "name"),
        "loaded_sample_limit": 200,
    }))
}
