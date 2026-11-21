//! The custom-extension (`local_cli_*`) half of the quarantine salvage.
//!
//! These tables can still SELECT after a full `quick_check` fails. Grant,
//! command and command-grant copies must all succeed so an allowed grant
//! never restores without its scoped catalog.

use std::path::Path;

use rusqlite::types::Value as SqlValue;
use rusqlite::Connection;

use super::{open_pair, placeholders, quote_columns, table_info};

#[cfg(test)]
#[path = "sqlite_store_salvage_local_cli_tests.rs"]
mod tests;

const LOCAL_CLI_TABLES: [&str; 6] = [
    "local_cli_authority",
    "local_cli_observation",
    "local_cli_grant",
    "local_cli_command",
    "local_cli_command_grant",
    "local_cli_grant_capability",
];
const REQUIRED_LOCAL_CLI_TABLES: [&str; 3] = [
    "local_cli_grant",
    "local_cli_command",
    "local_cli_command_grant",
];
/// Tables a partial copy cannot widen. A partial command or command-grant
/// copy could drop block rows and widen an allowed grant.
const PARTIAL_COPY_OK_TABLES: [&str; 4] = [
    "local_cli_authority",
    "local_cli_observation",
    "local_cli_grant",
    "local_cli_grant_capability",
];
/// A capability row rides along only with an allowed grant and a restored
/// cli-surface observation, the two facts the apply required to write it.
const ORPHAN_CAPABILITIES: &str = "delete from local_cli_grant_capability where cli_id not in \
     (select grant_row.cli_id from local_cli_grant as grant_row \
     join local_cli_observation as observed on observed.cli_id = grant_row.cli_id \
     where grant_row.state = 'allowed' and observed.surface = 'cli')";

pub(super) fn salvage_local_cli(source: &Path, destination: &Path) -> bool {
    let Some((src, mut dst)) = open_pair(source, destination) else {
        return false;
    };
    copy_local_cli(&src, &mut dst).unwrap_or(false)
}

fn copy_local_cli(src: &Connection, dst: &mut Connection) -> rusqlite::Result<bool> {
    let transaction = dst.transaction()?;
    let mut copied = Vec::new();
    for table in LOCAL_CLI_TABLES {
        match copy_allowlisted_table(src, &transaction, table) {
            Some(true) => copied.push(table),
            Some(false) => {}
            // The rolled-back transaction leaves nothing to commit.
            None => return Ok(false),
        }
    }
    if !REQUIRED_LOCAL_CLI_TABLES
        .iter()
        .all(|table| copied.contains(table))
    {
        return Ok(false);
    }
    // An observation that failed to copy leaves its capability an orphan.
    transaction.execute(ORPHAN_CAPABILITIES, [])?;
    transaction.commit()?;
    Ok(true)
}

/// `_copy_allowlisted_table`: the columns both stores share, row by row.
/// True when every row copied, or for a partial-copy table when any did.
///
/// `None` when an insert error rolled back the whole transaction, as
/// `SQLITE_FULL` or a `RAISE(ROLLBACK)` trigger can. Copying on would commit
/// each later row by itself, so an allowed grant could land without the
/// command blocks that scope it.
fn copy_allowlisted_table(src: &Connection, dst: &Connection, table: &str) -> Option<bool> {
    let partial_ok = PARTIAL_COPY_OK_TABLES.contains(&table);
    let (Ok(source), Ok(destination)) = (table_info(src, table), table_info(dst, table)) else {
        return Some(false);
    };
    let shared: Vec<&str> = destination
        .iter()
        .map(|column| column.name.as_str())
        .filter(|name| source.iter().any(|known| known.name == *name))
        .collect();
    if shared.is_empty() {
        return Some(false);
    }
    let quoted = quote_columns(&shared, ",");
    let Ok(mut select) = src.prepare(&format!("select {quoted} from \"{table}\"")) else {
        return Some(false);
    };
    let Ok(mut rows) = select.query([]) else {
        return Some(false);
    };
    let statement = format!(
        "insert or replace into \"{table}\" ({quoted}) values ({})",
        placeholders(shared.len())
    );
    let mut inserted = false;
    let mut saw_rows = false;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(_) => return Some(partial_ok && inserted),
        };
        saw_rows = true;
        let values = match (0..shared.len())
            .map(|index| row.get::<_, SqlValue>(index))
            .collect::<rusqlite::Result<Vec<_>>>()
        {
            Ok(values) => values,
            Err(_) => return Some(partial_ok && inserted),
        };
        match dst.execute(&statement, rusqlite::params_from_iter(values)) {
            Ok(_) => inserted = true,
            Err(_) if dst.is_autocommit() => return None,
            Err(_) if partial_ok => {}
            Err(_) => return Some(false),
        }
    }
    Some(inserted || !saw_rows)
}
