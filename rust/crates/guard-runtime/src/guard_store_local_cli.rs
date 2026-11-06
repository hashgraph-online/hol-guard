//! Observed custom-extension records: recording one sighting, forgetting an
//! un-enrolled record, the history-replay gate and retention pruning.
//!
//! Python supplies every timestamp. `clock` is the caller's wall-clock time,
//! used wherever the Python owner fell back to `datetime.now(timezone.utc)`.
//! Instants follow `parse_utc_timestamp`: stripped, a trailing `Z` read as
//! UTC, naive values read as UTC, and every comparison made on UTC instants.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, runtime_error, value_error, StoreResult};
use crate::guard_store_json::{py_str, py_strip};
use crate::guard_store_observed_mcp::is_local_cli_id;
use crate::policy_bundle_time::{from_isoformat, micros_to_utc_isoformat};

pub(crate) const RETENTION_DAYS: i64 = 30;
const MICROS_PER_DAY: i64 = 86_400_000_000;
const SURFACES: [&str; 3] = ["cli", "mcp", "package-scripts"];

/// Inventory rows and the digests derived from them. User grants are never
/// touched here.
const OBSERVATION_TABLES: [&str; 7] = [
    "local_cli_command",
    "local_mcp_catalog",
    "local_mcp_tool_authority",
    "local_mcp_provider_action",
    "local_mcp_provider_authority",
    "local_mcp_workflow_proposal",
    "local_cli_observation",
];

/// An observation can be forgotten only when nothing enrolled depends on it.
/// MCP connections sharing a server with an enrolled record stay; a legacy
/// server-wide row may store the server hash only as its identity hash.
const FORGETTABLE_PREDICATE: &str =
    "observation.cli_id not in (select cli_id from local_cli_grant) \
     and not (observation.surface = 'mcp' \
     and observation.server_identity_hash is not null \
     and observation.server_identity_hash in ( \
     select coalesce(enrolled.server_identity_hash, enrolled.identity_hash) \
     from local_cli_observation enrolled \
     join local_cli_grant grant_row on grant_row.cli_id = enrolled.cli_id \
     where enrolled.surface = 'mcp'))";

/// `parse_utc_timestamp` as UTC microseconds since the epoch.
pub(crate) fn parse_utc(value: &Value) -> Option<i64> {
    let stripped = py_strip(value.as_str()?);
    if stripped.is_empty() {
        return None;
    }
    let normalized = match stripped.strip_suffix(['Z', 'z']) {
        Some(prefix) => format!("{prefix}+00:00"),
        None => stripped.to_owned(),
    };
    from_isoformat(&normalized)?.utc_micros()
}

fn parse_text(value: Option<&str>) -> Option<i64> {
    parse_utc(&Value::from(value?))
}

/// A parsed instant, else the caller's clock.
pub(crate) fn instant_or_clock(value: Option<&str>, args: &Args) -> StoreResult<i64> {
    match parse_text(value) {
        Some(micros) => Ok(micros),
        None => match parse_text(Some(args.str("clock")?)) {
            Some(micros) => Ok(micros),
            None => value_error("invalid clock"),
        },
    }
}

/// `datetime +/- timedelta`, which raises once it leaves the datetime range.
fn shifted(micros: i64, delta: i64) -> StoreResult<i64> {
    match micros.checked_add(delta) {
        Some(moved) if micros_to_utc_isoformat(moved, "").is_some() => Ok(moved),
        _ => runtime_error("date value out of range"),
    }
}

fn ensure_retention_tables(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        "create table if not exists local_cli_forgotten (identity_hash text primary key, forgotten_at text not null);\
         create table if not exists local_cli_retention_state (\
         singleton integer primary key check (singleton = 1), last_pruned_at text not null)",
    )?;
    Ok(())
}

fn delete_observations(
    connection: &Connection,
    records: &[(String, String)],
    forgotten_at: Option<&str>,
) -> StoreResult<()> {
    ensure_retention_tables(connection)?;
    for table in OBSERVATION_TABLES {
        let sql = format!("delete from {table} where cli_id = ?");
        for (cli_id, _) in records {
            exec(connection, &sql, &[Value::from(cli_id.as_str())])?;
        }
    }
    let Some(forgotten_at) = forgotten_at else {
        return Ok(());
    };
    for (_, identity_hash) in records {
        exec(
            connection,
            "insert into local_cli_forgotten (identity_hash, forgotten_at) values (?, ?) \
             on conflict(identity_hash) do update set forgotten_at = excluded.forgotten_at",
            &[
                Value::from(identity_hash.as_str()),
                Value::from(forgotten_at),
            ],
        )?;
    }
    Ok(())
}

/// `prune_expired_local_cli_observations`: delete un-enrolled observations
/// last seen before `current - retention_days`. With `throttle` the scan
/// runs at most once a day.
pub(crate) fn prune(
    connection: &Connection,
    current: i64,
    retention_days: i64,
    throttle: bool,
) -> StoreResult<Vec<String>> {
    ensure_retention_tables(connection)?;
    if throttle {
        let row = query_one(
            connection,
            "select last_pruned_at from local_cli_retention_state where singleton = 1",
            &[],
        )?;
        let last = row.and_then(|row| row.get("last_pruned_at").and_then(parse_utc));
        if let Some(last) = last {
            if current < shifted(last, MICROS_PER_DAY)? {
                return Ok(Vec::new());
            }
        }
        let Some(stamp) = micros_to_utc_isoformat(current, "+00:00") else {
            return runtime_error("date value out of range");
        };
        exec(
            connection,
            "insert into local_cli_retention_state (singleton, last_pruned_at) values (1, ?) \
             on conflict(singleton) do update set last_pruned_at = excluded.last_pruned_at",
            &[Value::from(stamp)],
        )?;
    }
    let Some(span) = retention_days.checked_mul(MICROS_PER_DAY) else {
        return runtime_error("date value out of range");
    };
    let cutoff = shifted(current, -span)?;
    let rows = query_all(
        connection,
        &format!(
            "select observation.cli_id, observation.identity_hash, observation.last_seen_at \
             from local_cli_observation observation where {FORGETTABLE_PREDICATE}"
        ),
        &[],
    )?;
    let expired: Vec<(String, String)> = rows
        .iter()
        .filter(|row| {
            row.get("last_seen_at")
                .and_then(parse_utc)
                .is_some_and(|seen| seen < cutoff)
        })
        .map(|row| {
            let column = |name: &str| row.get(name).and_then(py_str).unwrap_or_default();
            (column("cli_id"), column("identity_hash"))
        })
        .collect();
    if !expired.is_empty() {
        // Expiry is not a Forget: recent history may still restore the record.
        delete_observations(connection, &expired, None)?;
    }
    Ok(expired.into_iter().map(|(cli_id, _)| cli_id).collect())
}

/// `replay_allowed`: a listed identity may always be refreshed; otherwise
/// entries older than the retention window before `now`, or no later than
/// when the user forgot the identity, are skipped.
pub(crate) fn replay_allowed(
    connection: &Connection,
    identity_hash: &str,
    seen_at: &str,
    now: Option<&str>,
    args: &Args,
) -> StoreResult<bool> {
    let listed = query_one(
        connection,
        "select 1 from local_cli_observation where identity_hash = ? limit 1",
        &[Value::from(identity_hash)],
    )?;
    if listed.is_some() {
        return Ok(true);
    }
    let seen = parse_text(Some(seen_at));
    let current = instant_or_clock(now, args)?;
    let cutoff = shifted(current, -RETENTION_DAYS * MICROS_PER_DAY)?;
    if seen.is_some_and(|seen| seen < cutoff) {
        return Ok(false);
    }
    ensure_retention_tables(connection)?;
    let row = query_one(
        connection,
        "select forgotten_at from local_cli_forgotten where identity_hash = ?",
        &[Value::from(identity_hash)],
    )?;
    let forgotten = row.and_then(|row| row.get("forgotten_at").and_then(parse_utc));
    Ok(match forgotten {
        None => true,
        Some(forgotten) => seen.is_some_and(|seen| seen > forgotten),
    })
}

pub(crate) fn opt(args: &Args, key: &str) -> StoreResult<Value> {
    Ok(args.opt_str(key)?.map_or(Value::Null, Value::from))
}

pub(crate) fn record_observation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid local CLI id");
    }
    let identity_hash = args.str("identity_hash")?;
    let seen_at = args.str("seen_at")?;
    let only_if_missing = args.flag("only_if_missing")?;
    let surface = args
        .opt_str("surface")?
        .filter(|surface| SURFACES.contains(surface))
        .unwrap_or("cli");
    let current = query_one(
        connection,
        "select observed_count from local_cli_observation where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    if current.is_some() && only_if_missing {
        return Ok(Value::Null);
    }
    if only_if_missing
        && !replay_allowed(
            connection,
            identity_hash,
            seen_at,
            args.opt_str("replayed_at")?,
            args,
        )?
    {
        return Ok(Value::Null);
    }
    let shared = [
        opt(args, "kind")?,
        opt(args, "name")?,
        opt(args, "interpreter_name")?,
        opt(args, "example_label")?,
    ];
    let optional = [
        opt(args, "source_path")?,
        opt(args, "help_status")?,
        Value::from(surface),
        opt(args, "server_identity_hash")?,
        opt(args, "server_command")?,
        opt(args, "server_args_hash")?,
    ];
    if current.is_none() {
        let mut params = vec![Value::from(cli_id), Value::from(identity_hash)];
        params.extend(shared);
        params.push(Value::from(seen_at));
        params.extend(optional);
        exec(
            connection,
            "insert into local_cli_observation ( \
                 cli_id, identity_hash, kind, name, interpreter_name, example_label, \
                 observed_count, last_seen_at, source_path, help_status, surface, \
                 server_identity_hash, server_command, server_args_hash \
             ) values (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?) \
             on conflict(cli_id) do nothing",
            &params,
        )?;
        if !only_if_missing {
            prune(
                connection,
                instant_or_clock(Some(seen_at), args)?,
                RETENTION_DAYS,
                true,
            )?;
        }
        return Ok(Value::Null);
    }
    clear_cause_of_other_identity(connection, cli_id, identity_hash)?;
    let mut params = vec![Value::from(identity_hash)];
    params.extend(shared);
    params.push(Value::from(seen_at));
    params.extend(optional);
    params.push(Value::from(cli_id));
    exec(
        connection,
        "update local_cli_observation \
         set identity_hash = ?, kind = ?, name = ?, interpreter_name = ?, \
             example_label = ?, observed_count = observed_count + 1, last_seen_at = ?, \
             source_path = coalesce(?, source_path), \
             help_status = coalesce(?, help_status), \
             surface = ?, \
             server_identity_hash = coalesce(?, server_identity_hash), \
             server_command = coalesce(?, server_command), \
             server_args_hash = coalesce(?, server_args_hash) \
         where cli_id = ?",
        &params,
    )?;
    prune(
        connection,
        instant_or_clock(Some(seen_at), args)?,
        RETENTION_DAYS,
        true,
    )?;
    Ok(Value::Null)
}

/// A blocked cause belongs to the identity whose run hit it, so a changed
/// identity starts without one. Stores that predate the column keep none.
fn clear_cause_of_other_identity(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
) -> StoreResult<()> {
    let has_cause = query_one(
        connection,
        "select 1 from pragma_table_info('local_cli_observation') \
         where name = 'first_blocked_cause'",
        &[],
    )?
    .is_some();
    if has_cause {
        exec(
            connection,
            "update local_cli_observation set first_blocked_cause = null \
             where cli_id = ? and identity_hash <> ?",
            &[Value::from(cli_id), Value::from(identity_hash)],
        )?;
    }
    Ok(())
}

/// Delete one un-enrolled record and its inventory rows, refusing with the
/// `LocalCliForgetError` code as the value-error message.
pub(crate) fn forget_observation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid_cli_id");
    }
    let identity_hash = args.str("identity_hash")?;
    let forgotten_at = args.str("clock")?;
    let Some(row) = query_one(
        connection,
        "select identity_hash from local_cli_observation where cli_id = ?",
        &[Value::from(cli_id)],
    )?
    else {
        return value_error("local_cli_not_found");
    };
    if row.get("identity_hash").and_then(py_str).as_deref() != Some(identity_hash) {
        return value_error("identity_changed");
    }
    let enrolled = query_one(
        connection,
        "select 1 from local_cli_grant where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    if enrolled.is_some() {
        return value_error("local_cli_enrolled");
    }
    let forgettable = query_one(
        connection,
        &format!(
            "select 1 from local_cli_observation observation \
             where observation.cli_id = ? and {FORGETTABLE_PREDICATE}"
        ),
        &[Value::from(cli_id)],
    )?;
    if forgettable.is_none() {
        return value_error("local_cli_shared_server_enrolled");
    }
    let record = [(cli_id.to_owned(), identity_hash.to_owned())];
    delete_observations(connection, &record, Some(forgotten_at))?;
    Ok(Value::Null)
}

pub(crate) fn replay_allowed_op(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let allowed = replay_allowed(
        connection,
        args.str("identity_hash")?,
        args.str("seen_at")?,
        args.opt_str("now")?,
        args,
    )?;
    Ok(Value::Bool(allowed))
}

pub(crate) fn prune_inactive(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let current = instant_or_clock(args.opt_str("now")?, args)?;
    let pruned = prune(
        connection,
        current,
        args.int("retention_days")?,
        args.flag("throttle")?,
    )?;
    Ok(Value::from(pruned))
}
