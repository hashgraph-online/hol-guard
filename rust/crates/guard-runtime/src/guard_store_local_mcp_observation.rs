//! Observed MCP connection records: finding the one record a launch maps to
//! and inserting or refreshing it without counting a sighting.
//!
//! A new host connection that matches a legacy server-wide record carries a
//! legacy Deny across. That write changes policy authority, so the first call
//! returns `need_barrier` without writing; Python closes the native policy
//! barrier and calls again with `barrier_closed`.

use rusqlite::{Connection, ErrorCode};
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_one, value_error, Row, StoreError, StoreResult,
};
use crate::guard_store_json::py_str;
use crate::guard_store_local_cli::{
    instant_or_clock, opt, parse_utc, prune, replay_allowed, RETENTION_DAYS,
};
use crate::guard_store_observed_mcp::is_local_cli_id;

const OBSERVATION_COLUMNS: &str = "cli_id, identity_hash, kind, name, interpreter_name, \
     example_label, server_identity_hash, server_command, server_args_hash, source_label";

/// A 64-hex identity hash, lowercased.
fn normalized_identity_hash(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.chars().count() != 64 {
        return None;
    }
    let lowered = value.to_lowercase();
    lowered
        .chars()
        .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        .then_some(lowered)
}

/// A stored observation, or `None` when its id or identity hash is not text.
fn observation(row: Row) -> Option<Row> {
    (row.get("cli_id").is_some_and(Value::is_string)
        && row.get("identity_hash").is_some_and(Value::is_string))
    .then_some(row)
}

fn find(
    connection: &Connection,
    cli_id: Option<&str>,
    server_identity_hash: Option<&str>,
    command: Option<&str>,
    args_hash: Option<&str>,
) -> StoreResult<Option<Row>> {
    let hash_value = normalized_identity_hash(server_identity_hash);
    let lookup_cli_id = cli_id.filter(|cli_id| is_local_cli_id(cli_id));
    let launch = command
        .filter(|command| !command.is_empty())
        .zip(args_hash.filter(|args_hash| !args_hash.is_empty()));
    // A stronger supplied identity must never fall through to a similar launch.
    let (predicate, params) = if let Some(cli_id) = lookup_cli_id {
        ("cli_id = ?", vec![Value::from(cli_id)])
    } else if let Some(hash) = hash_value {
        (
            "(server_identity_hash = ? or identity_hash = ?)",
            vec![Value::from(hash.as_str()), Value::from(hash)],
        )
    } else if let Some((command, args_hash)) = launch {
        (
            "server_command = ? and server_args_hash = ?",
            vec![Value::from(command), Value::from(args_hash)],
        )
    } else {
        return Ok(None);
    };
    let mut rows = query_all(
        connection,
        &format!(
            "select {OBSERVATION_COLUMNS} from local_cli_observation \
             where surface = 'mcp' and ({predicate}) \
             order by last_seen_at desc, cli_id asc limit 2"
        ),
        &params,
    )?;
    if rows.len() != 1 {
        return Ok(None);
    }
    Ok(observation(rows.remove(0)))
}

pub(crate) fn find_observation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let found = find(
        connection,
        args.opt_str("cli_id")?,
        args.opt_str("server_identity_hash")?,
        args.opt_str("command")?,
        args.opt_str("args_hash")?,
    )?;
    Ok(found.map_or(Value::Null, Value::Object))
}

/// The launch parameters shared by the legacy server-wide lookups.
fn legacy_params(launch: &Launch) -> Vec<Value> {
    vec![
        Value::from(launch.server_identity_hash),
        Value::from(launch.server_identity_hash),
        Value::from(launch.server_command),
        Value::from(launch.server_args_hash),
    ]
}

fn legacy_observation_exists(connection: &Connection, launch: &Launch) -> StoreResult<bool> {
    Ok(query_one(
        connection,
        "select 1 from local_cli_observation \
         where surface = 'mcp' and identity_hash = ? \
           and (server_identity_hash = ? or server_identity_hash is null) \
           and server_command = ? and server_args_hash = ? limit 1",
        &legacy_params(launch),
    )?
    .is_some())
}

fn matching_legacy_denial(connection: &Connection, launch: &Launch) -> StoreResult<bool> {
    Ok(query_one(
        connection,
        "select 1 from local_cli_observation observation \
         join local_cli_grant grant_row on grant_row.cli_id = observation.cli_id \
           and grant_row.identity_hash = observation.identity_hash \
         where observation.surface = 'mcp' and observation.identity_hash = ? \
           and (observation.server_identity_hash = ? or observation.server_identity_hash is null) \
           and observation.server_command = ? and observation.server_args_hash = ? \
           and (grant_row.state = 'blocked' or exists ( \
             select 1 from local_cli_command_grant choice \
             where choice.cli_id = observation.cli_id and choice.state = 'block')) \
         limit 1",
        &legacy_params(launch),
    )?
    .is_some())
}

/// A legacy Deny may cover multiple new host connections. Carry it to each;
/// old Allow authority never crosses the new connection identity boundary.
fn carry_legacy_denial(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
    seen_at: &str,
) -> StoreResult<()> {
    let inserted = exec(
        connection,
        "insert or ignore into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) \
         values (?, ?, 'blocked', 1, ?)",
        &[
            Value::from(cli_id),
            Value::from(identity_hash),
            Value::from(seen_at),
        ],
    )?;
    if inserted != 0 {
        exec(
            connection,
            "update local_cli_authority set revision = revision + 1 where singleton = 1",
            &[],
        )?;
    }
    Ok(())
}

fn collision_cli_id(identity_hash: &str) -> String {
    let prefix: String = identity_hash.chars().take(12).collect();
    format!("local-cli.mcp-{prefix}")
}

struct Launch<'a> {
    server_identity_hash: &'a str,
    server_command: &'a str,
    server_args_hash: &'a str,
}

/// Insert a fresh record; `None` when the id is invalid or already taken.
fn insert(
    connection: &Connection,
    args: &Args,
    target_id: &str,
    launch: &Launch,
) -> StoreResult<Option<String>> {
    if !is_local_cli_id(target_id) {
        return Ok(None);
    }
    let params = [
        Value::from(target_id),
        Value::from(args.str("identity_hash")?),
        opt(args, "kind")?,
        opt(args, "name")?,
        opt(args, "interpreter_name")?,
        opt(args, "example_label")?,
        Value::from(args.str("seen_at")?),
        Value::from(launch.server_identity_hash),
        Value::from(launch.server_command),
        Value::from(launch.server_args_hash),
        opt(args, "source_label")?,
    ];
    let outcome = exec(
        connection,
        "insert into local_cli_observation ( \
             cli_id, identity_hash, kind, name, interpreter_name, example_label, \
             observed_count, last_seen_at, source_path, help_status, surface, \
             server_identity_hash, server_command, server_args_hash, source_label \
         ) values (?, ?, ?, ?, ?, ?, 1, ?, null, null, 'mcp', ?, ?, ?, ?)",
        &params,
    );
    match outcome {
        Ok(_) => Ok(Some(target_id.to_owned())),
        Err(StoreError::Sqlite(error))
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// `later_timestamp`: the stored value unless the replayed one is later.
fn later_timestamp(current: Option<&Value>, candidate: &str) -> Value {
    let stored = current.and_then(parse_utc);
    let replayed = parse_utc(&Value::from(candidate));
    match (current, stored) {
        (Some(current), Some(stored)) if replayed.is_none_or(|replayed| replayed <= stored) => {
            current.clone()
        }
        _ => Value::from(candidate),
    }
}

fn written(cli_id: String) -> Value {
    json!({ "cli_id": cli_id })
}

/// `ensure_local_mcp_observation`: insert or refresh one MCP record without
/// incrementing `observed_count`. With `replayed`, `seen_at` is a history
/// timestamp: it never moves `last_seen_at` backward and skips pruning.
pub(crate) fn ensure_observation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid local CLI id");
    }
    let identity_hash = args.str("identity_hash")?;
    let seen_at = args.str("seen_at")?;
    let launch = Launch {
        server_identity_hash: args.str("server_identity_hash")?,
        server_command: args.str("server_command")?,
        server_args_hash: args.str("server_args_hash")?,
    };
    let connection_identity_hash = args
        .opt_str("connection_identity_hash")?
        .filter(|hash| !hash.is_empty());
    let replayed = args.flag("replayed")?;
    let mut existing = find(
        connection,
        None,
        Some(connection_identity_hash.unwrap_or(launch.server_identity_hash)),
        Some(launch.server_command),
        Some(launch.server_args_hash),
    )?;
    let legacy_candidate = existing.is_none()
        && connection_identity_hash.is_some_and(|hash| hash != launch.server_identity_hash)
        && legacy_observation_exists(connection, &launch)?;
    if legacy_candidate && !args.flag("barrier_closed")? {
        return Ok(json!({ "need_barrier": true }));
    }
    if replayed
        && !replay_allowed(
            connection,
            identity_hash,
            seen_at,
            args.opt_str("replay_now")?,
            args,
        )?
    {
        return Ok(json!({ "replay_skipped": true }));
    }
    let legacy_deny = legacy_candidate && matching_legacy_denial(connection, &launch)?;
    if existing.is_none() {
        if let Some(inserted) = insert(connection, args, cli_id, &launch)? {
            if legacy_deny {
                carry_legacy_denial(connection, &inserted, identity_hash, seen_at)?;
            }
            if !replayed {
                let current = instant_or_clock(Some(seen_at), args)?;
                prune(connection, current, RETENTION_DAYS, true)?;
            }
            return Ok(written(inserted));
        }
        let Some(row) = query_one(
            connection,
            &format!("select {OBSERVATION_COLUMNS} from local_cli_observation where cli_id = ?"),
            &[Value::from(cli_id)],
        )?
        .and_then(observation) else {
            return Ok(written(cli_id.to_owned()));
        };
        if row.get("identity_hash").and_then(Value::as_str) != Some(identity_hash) {
            let retry = insert(connection, args, &collision_cli_id(identity_hash), &launch)?;
            if let Some(retry) = retry {
                if legacy_deny {
                    carry_legacy_denial(connection, &retry, identity_hash, seen_at)?;
                }
                return Ok(written(retry));
            }
            return Ok(written(
                row.get("cli_id").and_then(py_str).unwrap_or_default(),
            ));
        }
        existing = Some(row);
    }
    let row = existing.unwrap_or_default();
    let target = row.get("cli_id").and_then(py_str).unwrap_or_default();
    if legacy_deny && row.get("identity_hash").and_then(Value::as_str) == Some(identity_hash) {
        carry_legacy_denial(connection, &target, identity_hash, seen_at)?;
    }
    let refreshed_at = if replayed {
        let stored = query_one(
            connection,
            "select last_seen_at from local_cli_observation where cli_id = ?",
            &[Value::from(target.as_str())],
        )?;
        later_timestamp(
            stored.as_ref().and_then(|row| row.get("last_seen_at")),
            seen_at,
        )
    } else {
        Value::from(seen_at)
    };
    exec(
        connection,
        "update local_cli_observation \
         set name = ?, example_label = ?, last_seen_at = ?, \
             server_identity_hash = coalesce(server_identity_hash, ?), \
             server_command = coalesce(server_command, ?), \
             server_args_hash = coalesce(server_args_hash, ?), \
             source_label = coalesce(?, source_label) \
         where cli_id = ?",
        &[
            opt(args, "name")?,
            opt(args, "example_label")?,
            refreshed_at,
            Value::from(launch.server_identity_hash),
            Value::from(launch.server_command),
            Value::from(launch.server_args_hash),
            opt(args, "source_label")?,
            Value::from(target.as_str()),
        ],
    )?;
    if !replayed {
        let current = instant_or_clock(Some(seen_at), args)?;
        prune(connection, current, RETENTION_DAYS, true)?;
    }
    Ok(written(target))
}
