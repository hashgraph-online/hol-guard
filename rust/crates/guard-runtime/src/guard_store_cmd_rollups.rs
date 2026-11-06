//! Transactional daily rollups for command activity facts. Every function
//! runs inside the caller's SQLite transaction, as the Python original did.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_wire::text_of;
use crate::guard_store_db::{
    exec, query_all, query_one, runtime_error, text, Row, StoreError, StoreResult,
};

/// `(dimension, value)` cell counts in first-seen order.
#[derive(Default)]
pub(crate) struct Cells(Vec<((String, String), i64)>);

impl Cells {
    fn add(&mut self, dimension: &str, value: &str, delta: i64) {
        let key = (dimension.to_owned(), value.to_owned());
        match self.0.iter_mut().find(|(cell, _)| *cell == key) {
            Some((_, count)) => *count += delta,
            None => self.0.push((key, delta)),
        }
    }

    fn get(&self, dimension: &str, value: &str) -> i64 {
        self.0
            .iter()
            .find(|((d, v), _)| d == dimension && v == value)
            .map_or(0, |(_, count)| *count)
    }
}

/// The lifecycle-mutable and fixed cells of one activity row or wire value.
fn base_cells(activity: &Map<String, Value>) -> StoreResult<Cells> {
    let prompted = match activity.get("prompted") {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_i64().unwrap_or(0) != 0,
        _ => false,
    };
    let mut cells = Cells::default();
    cells.add("harness", text_of(activity, "harness")?, 1);
    cells.add(
        "execution_status",
        text_of(activity, "execution_status")?,
        1,
    );
    cells.add(
        "prompt_status",
        if prompted { "prompted" } else { "not_prompted" },
        1,
    );
    cells.add("proof_level", text_of(activity, "proof_level")?, 1);
    let evaluation = text_of(activity, "evaluation_latency_bucket")?;
    cells.add("latency", &format!("evaluation.{evaluation}"), 1);
    let persistence = text_of(activity, "persistence_latency_bucket")?;
    cells.add("latency", &format!("persistence.{persistence}"), 1);
    if let Some(action) = activity.get("policy_action").and_then(Value::as_str) {
        cells.add("disposition", action, 1);
    }
    Ok(cells)
}

fn add_match_cells(cells: &mut Cells, matches: &[(String, String)]) {
    let mut seen: Vec<&str> = Vec::new();
    for (extension, _) in matches {
        if !seen.contains(&extension.as_str()) {
            seen.push(extension);
            cells.add("extension", extension, 1);
        }
    }
    for (_, rule) in matches {
        cells.add("rule", rule, 1);
    }
}

fn day_of(occurred_at: &str) -> String {
    occurred_at.chars().take(10).collect()
}

fn claim_membership(
    connection: &Connection,
    activity_id: &str,
    day: &str,
    occurred_at: &str,
    rolled_at: &str,
) -> StoreResult<bool> {
    Ok(exec(
        connection,
        "insert or ignore into command_activity_rollup_membership \
         (activity_id, day, occurred_at, rolled_at) values (?, ?, ?, ?)",
        &[
            Value::from(activity_id),
            Value::from(day),
            Value::from(occurred_at),
            Value::from(rolled_at),
        ],
    )? == 1)
}

fn increment_total(connection: &Connection, day: &str, delta: i64) -> StoreResult<()> {
    exec(
        connection,
        "insert into command_activity_daily_totals (day, total) values (?, ?) \
         on conflict(day) do update set total = total + excluded.total",
        &[Value::from(day), Value::from(delta)],
    )?;
    Ok(())
}

fn apply_deltas(connection: &Connection, day: &str, deltas: &Cells) -> StoreResult<()> {
    for ((dimension, value), count) in &deltas.0 {
        if *count > 0 {
            exec(
                connection,
                "insert into command_activity_daily_rollups (day, dimension, dimension_value, count) \
                 values (?, ?, ?, ?) on conflict(day, dimension, dimension_value) \
                 do update set count = count + excluded.count",
                &[
                    Value::from(day),
                    Value::from(dimension.as_str()),
                    Value::from(value.as_str()),
                    Value::from(*count),
                ],
            )?;
        }
    }
    for ((dimension, value), count) in &deltas.0 {
        if *count >= 0 {
            continue;
        }
        let changed = exec(
            connection,
            "update command_activity_daily_rollups set count = count + ? \
             where day = ? and dimension = ? and dimension_value = ?",
            &[
                Value::from(*count),
                Value::from(day),
                Value::from(dimension.as_str()),
                Value::from(value.as_str()),
            ],
        )?;
        if changed != 1 {
            return runtime_error("command activity rollup delta referenced a missing cell");
        }
    }
    exec(
        connection,
        "delete from command_activity_daily_rollups where day = ? and count = 0",
        &[Value::from(day)],
    )?;
    let negative = query_one(
        connection,
        "select 1 as present from command_activity_daily_rollups where day = ? and count < 0 limit 1",
        &[Value::from(day)],
    )?;
    if negative.is_some() {
        return runtime_error("command activity rollup delta produced a negative count");
    }
    Ok(())
}

/// Add one new activity to its daily cells exactly once.
pub(crate) fn record_insert(
    connection: &Connection,
    activity: &Map<String, Value>,
    matches: &[(String, String)],
) -> StoreResult<bool> {
    let occurred_at = text_of(activity, "occurred_at")?;
    let day = day_of(occurred_at);
    if !claim_membership(
        connection,
        text_of(activity, "activity_id")?,
        &day,
        occurred_at,
        occurred_at,
    )? {
        return Ok(false);
    }
    increment_total(connection, &day, 1)?;
    let mut cells = base_cells(activity)?;
    add_match_cells(&mut cells, matches);
    apply_deltas(connection, &day, &cells)?;
    Ok(true)
}

fn persisted_matches(
    connection: &Connection,
    activity_id: &str,
) -> StoreResult<Vec<(String, String)>> {
    Ok(query_all(
        connection,
        "select extension_id, rule_id from command_activity_matches where activity_id = ?",
        &[Value::from(activity_id)],
    )?
    .iter()
    .map(|row| {
        (
            text(row, "extension_id").to_owned(),
            text(row, "rule_id").to_owned(),
        )
    })
    .collect())
}

/// Roll a persisted activity that predates membership, then move lifecycle cells.
pub(crate) fn record_transition(
    connection: &Connection,
    previous: &Map<String, Value>,
    current: &Map<String, Value>,
) -> StoreResult<()> {
    let activity_id = text_of(previous, "activity_id")?;
    let occurred_at = text_of(previous, "occurred_at")?;
    let day = day_of(occurred_at);
    if claim_membership(connection, activity_id, &day, occurred_at, occurred_at)? {
        increment_total(connection, &day, 1)?;
        let mut cells = base_cells(previous)?;
        add_match_cells(&mut cells, &persisted_matches(connection, activity_id)?);
        apply_deltas(connection, &day, &cells)?;
    }
    let (before, after) = (base_cells(previous)?, base_cells(current)?);
    let mut deltas = Cells::default();
    for (cell, _) in before.0.iter().chain(after.0.iter()) {
        let delta = after.get(&cell.0, &cell.1) - before.get(&cell.0, &cell.1);
        if delta != 0 && deltas.get(&cell.0, &cell.1) == 0 {
            deltas.add(&cell.0, &cell.1, delta);
        }
    }
    apply_deltas(connection, &day, &deltas)
}

fn raw_cells(connection: &Connection, row: &Row) -> StoreResult<Cells> {
    let mut cells = base_cells(row)?;
    add_match_cells(
        &mut cells,
        &persisted_matches(connection, text(row, "activity_id"))?,
    );
    Ok(cells)
}

fn roll_raw(connection: &Connection, row: &Row, rolled_at: &str) -> StoreResult<bool> {
    let occurred_at = text(row, "occurred_at");
    let day = day_of(occurred_at);
    if !claim_membership(
        connection,
        text(row, "activity_id"),
        &day,
        occurred_at,
        rolled_at,
    )? {
        return Ok(false);
    }
    increment_total(connection, &day, 1)?;
    apply_deltas(connection, &day, &raw_cells(connection, row)?)?;
    Ok(true)
}

/// Outcome of one bounded backfill batch.
pub(crate) struct Backfill {
    pub(crate) rolled: i64,
    pub(crate) cursor_occurred_at: Option<String>,
    pub(crate) cursor_activity_id: Option<String>,
    pub(crate) cursor_complete: bool,
    pub(crate) complete: bool,
}

pub(crate) struct Cursor {
    pub(crate) occurred_at: Option<String>,
    pub(crate) activity_id: Option<String>,
    pub(crate) complete: bool,
}

pub(crate) fn backfill_batch(
    connection: &Connection,
    batch_size: i64,
    rolled_at: &str,
    cursor: &Cursor,
) -> StoreResult<Backfill> {
    if batch_size < 1 {
        return Err(StoreError::Value("batch_size must be positive".to_owned()));
    }
    if cursor.occurred_at.is_some() != cursor.activity_id.is_some() {
        return Err(StoreError::Value(
            "backfill cursor fields must both be present or absent".to_owned(),
        ));
    }
    let budget = if cursor.complete {
        0
    } else {
        (batch_size / 2).max(1)
    };
    let mut rows: Vec<Row> = Vec::new();
    if budget > 0 {
        rows = match (&cursor.occurred_at, &cursor.activity_id) {
            (Some(at), Some(id)) => query_all(
                connection,
                "select * from command_activity where (occurred_at, activity_id) > (?, ?) \
                 order by occurred_at, activity_id limit ?",
                &[
                    Value::from(at.as_str()),
                    Value::from(id.as_str()),
                    Value::from(budget),
                ],
            )?,
            _ => query_all(
                connection,
                "select * from command_activity order by occurred_at, activity_id limit ?",
                &[Value::from(budget)],
            )?,
        };
    }
    let legacy_complete = cursor.complete || (rows.len() as i64) < budget;
    let remaining = batch_size - rows.len() as i64;
    let pending = query_all(
        connection,
        "select activity.* from command_activity_rollup_pending as pending \
         join command_activity as activity on activity.activity_id = pending.activity_id \
         order by pending.activity_id limit ?",
        &[Value::from(remaining)],
    )?;
    let mut rolled = 0;
    for row in &rows {
        rolled += i64::from(roll_raw(connection, row, rolled_at)?);
    }
    for row in &pending {
        rolled += i64::from(roll_raw(connection, row, rolled_at)?);
        exec(
            connection,
            "delete from command_activity_rollup_pending where activity_id = ?",
            &[Value::from(text(row, "activity_id"))],
        )?;
    }
    let last = rows.last();
    Ok(Backfill {
        rolled,
        cursor_occurred_at: last
            .map(|row| text(row, "occurred_at").to_owned())
            .or_else(|| cursor.occurred_at.clone()),
        cursor_activity_id: last
            .map(|row| text(row, "activity_id").to_owned())
            .or_else(|| cursor.activity_id.clone()),
        cursor_complete: legacy_complete,
        complete: (pending.len() as i64) < remaining && legacy_complete,
    })
}

pub(crate) fn detail_compaction_started(connection: &Connection) -> StoreResult<bool> {
    Ok(query_one(
        connection,
        "select detail_compaction_started_at as started from command_activity_maintenance \
         where singleton = 1",
        &[],
    )?
    .is_some_and(|row| !matches!(row.get("started"), None | Some(Value::Null))))
}

/// `(day, dimension, value) -> count` over retained detail rows.
const CELLS_SQL: &str = "select day, dimension, dimension_value, count(*) as count from ( \
  select substr(occurred_at, 1, 10) as day, 'harness' as dimension, harness as dimension_value \
    from command_activity \
  union all select substr(occurred_at, 1, 10), 'disposition', policy_action \
    from command_activity where policy_action is not null \
  union all select substr(occurred_at, 1, 10), 'execution_status', execution_status \
    from command_activity \
  union all select substr(occurred_at, 1, 10), 'prompt_status', \
    case when prompted = 1 then 'prompted' else 'not_prompted' end from command_activity \
  union all select substr(occurred_at, 1, 10), 'proof_level', proof_level from command_activity \
  union all select substr(occurred_at, 1, 10), 'latency', \
    'evaluation.' || evaluation_latency_bucket from command_activity \
  union all select substr(occurred_at, 1, 10), 'latency', \
    'persistence.' || persistence_latency_bucket from command_activity \
  union all select extension.day, 'extension', extension.extension_id from ( \
    select distinct activity.activity_id, substr(activity.occurred_at, 1, 10) as day, \
      matches.extension_id \
    from command_activity as activity \
    join command_activity_matches as matches on matches.activity_id = activity.activity_id \
  ) as extension \
  union all select substr(activity.occurred_at, 1, 10), 'rule', matches.rule_id \
    from command_activity as activity \
    join command_activity_matches as matches on matches.activity_id = activity.activity_id \
) group by day, dimension, dimension_value";

pub(crate) fn rebuild(connection: &Connection, rebuilt_at: &str) -> StoreResult<()> {
    if detail_compaction_started(connection)? {
        return runtime_error("rollups cannot be rebuilt after detail compaction");
    }
    for table in [
        "command_activity_daily_totals",
        "command_activity_daily_rollups",
        "command_activity_rollup_membership",
    ] {
        exec(connection, &format!("delete from {table}"), &[])?;
    }
    exec(
        connection,
        "insert into command_activity_daily_totals (day, total) \
         select substr(occurred_at, 1, 10), count(*) from command_activity \
         group by substr(occurred_at, 1, 10)",
        &[],
    )?;
    exec(
        connection,
        &format!(
            "insert into command_activity_daily_rollups (day, dimension, dimension_value, count) \
             {CELLS_SQL}"
        ),
        &[],
    )?;
    exec(
        connection,
        "insert into command_activity_rollup_membership (activity_id, day, occurred_at, rolled_at) \
         select activity_id, substr(occurred_at, 1, 10), occurred_at, ? from command_activity",
        &[Value::from(rebuilt_at)],
    )?;
    exec(
        connection,
        "update command_activity_maintenance set last_completed_day = null, \
         rollup_backfill_cursor_occurred_at = null, rollup_backfill_cursor_activity_id = null, \
         rollup_backfill_complete = 1 where singleton = 1",
        &[],
    )?;
    Ok(())
}

fn count_map(
    connection: &Connection,
    sql: &str,
    keys: &[&str],
) -> StoreResult<BTreeMap<Vec<String>, i64>> {
    Ok(query_all(connection, sql, &[])?
        .iter()
        .map(|row| {
            let key = keys
                .iter()
                .map(|column| match row.get(*column) {
                    Some(Value::String(value)) => value.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                })
                .collect();
            (key, row.get("count").and_then(Value::as_i64).unwrap_or(0))
        })
        .collect())
}

pub(crate) fn reconciled(connection: &Connection) -> StoreResult<bool> {
    if detail_compaction_started(connection)? {
        return Ok(false);
    }
    let expected = count_map(
        connection,
        "select substr(occurred_at, 1, 10) as day, count(*) as count from command_activity \
         group by substr(occurred_at, 1, 10)",
        &["day"],
    )?;
    let actual = count_map(
        connection,
        "select day, total as count from command_activity_daily_totals",
        &["day"],
    )?;
    if expected != actual {
        return Ok(false);
    }
    let keys = ["day", "dimension", "dimension_value"];
    Ok(count_map(connection, CELLS_SQL, &keys)?
        == count_map(
            connection,
            "select day, dimension, dimension_value, count from command_activity_daily_rollups",
            &keys,
        )?)
}
