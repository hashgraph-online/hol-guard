//! `store_local_cli.replace_local_cli_commands` /
//! `merge_local_cli_commands`: the command rows, the grant pruning they force
//! and the review sweep a changed MCP tool forces.
//!
//! Python runs all of it inside one `begin immediate`, and it has to stay that
//! way. The command rows, the catalog snapshot
//! (`guard_store_local_cli_mcp_snapshot`), the per-tool authority digests and
//! the review states a changed tool forces are four views of one discovery:
//! review states written without the snapshot would ask about tools that are
//! no longer listed.

use std::collections::HashSet;

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_one, text, value_error, StoreError, StoreResult,
};
use crate::guard_store_json::py_prefix;
use crate::guard_store_local_cli_mcp_snapshot::write_mcp_catalog;
use crate::guard_store_observed_mcp::is_local_cli_id;
use crate::local_mcp_grant_identity::is_command_id;

/// Every shape error the args carry, as the surrounding ops report them.
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// One `LocalCliCommand` as it crosses the wire.
struct Command<'a> {
    command_id: &'a str,
    name: &'a str,
    usage: &'a str,
    description: &'a str,
    parent_id: Option<&'a str>,
}

fn commands<'a>(args: &Args<'a>) -> StoreResult<Vec<Command<'a>>> {
    let Some(Value::Array(items)) = args.raw("commands") else {
        return Err(INVALID);
    };
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        let (
            Some(Value::String(command_id)),
            Some(Value::String(name)),
            Some(Value::String(usage)),
            Some(Value::String(description)),
        ) = (
            item.get("command_id"),
            item.get("name"),
            item.get("usage"),
            item.get("description"),
        )
        else {
            return Err(INVALID);
        };
        let parent_id = match item.get("parent_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(parent)) => Some(parent.as_str()),
            Some(_) => return Err(INVALID),
        };
        parsed.push(Command {
            command_id,
            name,
            usage,
            description,
            parent_id,
        });
    }
    Ok(parsed)
}

/// `replace_local_cli_commands` and `merge_local_cli_commands`. They share the
/// MCP catalog write and the review sweep; they differ in whether the stored
/// command rows are rebuilt or appended to.
pub(crate) fn write_local_cli_catalog(
    connection: &Connection,
    args: &Args<'_>,
    merging: bool,
) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid local CLI id");
    }
    let limit = if merging { args.int("limit")? } else { 0 };
    if merging && limit < 1 {
        return value_error("invalid local CLI catalog");
    }
    let commands = commands(args)?;
    let seen_at = args.opt_str("seen_at")?;

    let catalog = match args.raw("mcp_catalog") {
        None | Some(Value::Null) => None,
        Some(Value::Object(catalog)) => Some(catalog),
        Some(_) => return Err(INVALID),
    };
    let review_ids = match catalog {
        None => Vec::new(),
        Some(catalog) => write_mcp_catalog(
            connection,
            cli_id,
            catalog,
            args.opt_str("identity_hash")?,
            seen_at,
            match args.raw("expected_catalog_revision") {
                None | Some(Value::Null) => None,
                Some(value) => Some(value.as_i64().ok_or(INVALID)?),
            },
        )?,
    };

    let known = if merging {
        merge_commands(connection, cli_id, &commands, limit)?
    } else {
        replace_commands(connection, cli_id, &commands)?
    };
    review_catalog_changes(connection, cli_id, &review_ids, &known, seen_at)?;
    if !merging {
        prune_command_grants(connection, cli_id, &known, catalog.is_some())?;
    }
    Ok(Value::Null)
}

/// `delete from local_cli_command` followed by the ordered reinsert.
fn replace_commands(
    connection: &Connection,
    cli_id: &str,
    commands: &[Command<'_>],
) -> StoreResult<HashSet<String>> {
    exec(
        connection,
        "delete from local_cli_command where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    let mut known = HashSet::with_capacity(commands.len());
    for (index, command) in commands.iter().enumerate() {
        if !is_command_id(command.command_id) {
            return value_error("invalid local CLI command id");
        }
        insert_command(connection, cli_id, command, index as i64)?;
        known.insert(command.command_id.to_owned());
    }
    Ok(known)
}

/// `merge_local_cli_commands`: append what is new, keep what is stored, and
/// refuse the whole batch when the union would outgrow the catalog bound.
fn merge_commands(
    connection: &Connection,
    cli_id: &str,
    commands: &[Command<'_>],
    limit: i64,
) -> StoreResult<HashSet<String>> {
    let rows = query_all(
        connection,
        "select command_id from local_cli_command where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    let mut known: HashSet<String> = rows
        .iter()
        .map(|row| text(row, "command_id").to_owned())
        .collect();
    if commands
        .iter()
        .any(|command| !is_command_id(command.command_id))
    {
        return value_error("invalid local CLI command id");
    }
    let incoming: HashSet<&str> = commands.iter().map(|command| command.command_id).collect();
    let union = known.len() + incoming.iter().filter(|id| !known.contains(**id)).count();
    if union as i64 > limit {
        // The Python raise is `LocalCliCatalogLimitError`, a `ValueError`
        // subclass the caller catches by this exact message.
        return value_error("local_cli_catalog_limit");
    }
    for command in commands {
        if known.contains(command.command_id) {
            continue;
        }
        insert_command(connection, cli_id, command, known.len() as i64)?;
        known.insert(command.command_id.to_owned());
    }
    Ok(known)
}

fn insert_command(
    connection: &Connection,
    cli_id: &str,
    command: &Command<'_>,
    sort_index: i64,
) -> StoreResult<()> {
    exec(
        connection,
        "insert into local_cli_command \
         (cli_id, command_id, name, usage, description, parent_id, sort_index) \
         values (?, ?, ?, ?, ?, ?, ?)",
        &[
            Value::from(cli_id),
            Value::from(command.command_id),
            Value::from(py_prefix(command.name, 120)),
            Value::from(py_prefix(command.usage, 160)),
            Value::from(py_prefix(command.description, 240)),
            command.parent_id.map_or(Value::Null, Value::from),
            Value::from(sort_index),
        ],
    )?;
    Ok(())
}

/// Drop per-command decisions for commands the extension no longer lists. A
/// catalog write keeps explicit Deny and pending review rows as tombstones, so
/// a tool that comes back cannot recover an old Allow or escape a Deny.
fn prune_command_grants(
    connection: &Connection,
    cli_id: &str,
    known: &HashSet<String>,
    has_catalog: bool,
) -> StoreResult<()> {
    let rows = query_all(
        connection,
        "select command_id, state from local_cli_command_grant where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    for row in &rows {
        let command_id = text(row, "command_id");
        let state = text(row, "state");
        if has_catalog && matches!(state, "block" | "review") {
            continue;
        }
        if !known.contains(command_id) {
            exec(
                connection,
                "delete from local_cli_command_grant where cli_id = ? and command_id = ?",
                &[Value::from(cli_id), Value::from(command_id)],
            )?;
        }
    }
    Ok(())
}

/// `review_catalog_changes`: reset changed or new authority to Ask while
/// retaining an explicit Deny, then move the grant revision so a resident
/// holding the old one re-reads.
fn review_catalog_changes(
    connection: &Connection,
    cli_id: &str,
    review_ids: &[String],
    known: &HashSet<String>,
    seen_at: Option<&str>,
) -> StoreResult<()> {
    if review_ids.is_empty() {
        return Ok(());
    }
    let saved: HashSet<String> = query_all(
        connection,
        "select command_id from local_cli_command_grant where cli_id = ?",
        &[Value::from(cli_id)],
    )?
    .iter()
    .map(|row| text(row, "command_id").to_owned())
    .collect();
    let mut pending: Vec<&str> = review_ids
        .iter()
        .map(String::as_str)
        .filter(|id| known.contains(*id) || saved.contains(*id))
        .collect();
    pending.sort_unstable();
    pending.dedup();
    let mut changed = false;
    for command_id in pending {
        let previous = query_one(
            connection,
            "select state from local_cli_command_grant where cli_id = ? and command_id = ?",
            &[Value::from(cli_id), Value::from(command_id)],
        )?;
        if previous
            .as_ref()
            .is_some_and(|row| matches!(text(row, "state"), "block" | "review"))
        {
            continue;
        }
        exec(
            connection,
            "insert into local_cli_command_grant (cli_id, command_id, state) values (?, ?, 'review') \
             on conflict(cli_id, command_id) do update set state = 'review'",
            &[Value::from(cli_id), Value::from(command_id)],
        )?;
        changed = true;
    }
    if !changed {
        return Ok(());
    }
    let grant = query_one(
        connection,
        "select 1 as present from local_cli_grant where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    if grant.is_none() {
        return Ok(());
    }
    exec(
        connection,
        "update local_cli_authority set revision = revision + 1 where singleton = 1",
        &[],
    )?;
    exec(
        connection,
        "update local_cli_grant set revision = \
         (select revision from local_cli_authority where singleton = 1), updated_at = ? \
         where cli_id = ?",
        &[
            seen_at.map_or(Value::Null, Value::from),
            Value::from(cli_id),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "guard_store_local_cli_catalog_tests.rs"]
mod tests;
