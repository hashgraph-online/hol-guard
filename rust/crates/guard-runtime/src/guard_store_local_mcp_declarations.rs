//! `reconcile_remote_mcp_declarations`: forget remote declarations a fresh
//! harness config scan no longer finds.
//!
//! A remote connector removed from a harness config keeps its record, so its
//! permission history and decisions stay. Only the declaration goes: the
//! `<harness>:remote` source for every harness the scan read, and the stored
//! origin once no harness declares the connector as remote any more.

use std::collections::BTreeSet;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, value_error, StoreError, StoreResult};
use crate::guard_store_local_mcp_observation::valid_declared_source;

/// Harnesses one scan can read; a longer list is not a scan Guard made.
const MAX_HARNESSES: usize = 64;
/// Matches the discovery cap with room for duplicate identities.
const MAX_DECLARED: usize = 512;

pub(crate) fn reconcile_remote_declarations(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    let harnesses = args.strings("harnesses")?.unwrap_or_default();
    let declared = args.strings("declared_cli_ids")?.unwrap_or_default();
    if harnesses.len() > MAX_HARNESSES
        || declared.len() > MAX_DECLARED
        || harnesses
            .iter()
            .any(|harness| !valid_declared_source(&format!("{harness}:remote")))
    {
        return value_error("invalid MCP declaration scan");
    }
    let scanned: BTreeSet<String> = harnesses
        .iter()
        .map(|harness| format!("{harness}:remote"))
        .collect();
    let declared: BTreeSet<&str> = declared.into_iter().collect();
    let rows = query_all(
        connection,
        "select cli_id, remote_origin, declared_sources_json from local_cli_observation \
         where remote_origin is not null or declared_sources_json like '%:remote%'",
        &[],
    )?;
    let mut cleared = 0_i64;
    for row in rows {
        let Some(cli_id) = row.get("cli_id").and_then(Value::as_str) else {
            continue;
        };
        if declared.contains(cli_id) {
            continue;
        }
        let stored: Vec<String> = row
            .get("declared_sources_json")
            .and_then(Value::as_str)
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        let kept: Vec<String> = stored
            .iter()
            .filter(|source| !scanned.contains(source.as_str()))
            .cloned()
            .collect();
        let origin = row
            .get("remote_origin")
            .is_some_and(|value| !value.is_null());
        let still_remote = kept.iter().any(|source| source.ends_with(":remote"));
        if kept.len() == stored.len() && (still_remote || !origin) {
            continue;
        }
        let encoded =
            if kept.is_empty() {
                Value::Null
            } else {
                Value::from(serde_json::to_string(&kept).map_err(|_| {
                    StoreError::Invalid("native_guard_store_declared_sources_invalid")
                })?)
            };
        cleared += exec(
            connection,
            "update local_cli_observation set declared_sources_json = ?, \
             remote_origin = case when ? then remote_origin else null end \
             where cli_id = ?",
            &[encoded, Value::from(still_remote), Value::from(cli_id)],
        )?;
    }
    Ok(json!({ "reconciled": cleared }))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use serde_json::{json, Map, Value};

    use super::reconcile_remote_declarations;
    use crate::guard_store_args::Args;

    fn store(rows: &[(&str, Option<&str>, Option<&str>)]) -> Connection {
        let connection = Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch(
                "create table local_cli_observation (cli_id text primary key, \
                 remote_origin text, declared_sources_json text)",
            )
            .expect("schema");
        for (cli_id, origin, sources) in rows {
            connection
                .execute(
                    "insert into local_cli_observation values (?, ?, ?)",
                    rusqlite::params![cli_id, origin, sources],
                )
                .expect("row");
        }
        connection
    }

    fn reconcile(connection: &Connection, harnesses: &[&str], declared: &[&str]) {
        let args: Map<String, Value> =
            json!({"harnesses": harnesses, "declared_cli_ids": declared})
                .as_object()
                .cloned()
                .expect("object");
        reconcile_remote_declarations(connection, &Args(&args)).expect("reconciled");
    }

    fn row(connection: &Connection, cli_id: &str) -> (Option<String>, Option<String>) {
        connection
            .query_row(
                "select remote_origin, declared_sources_json from local_cli_observation where cli_id = ?",
                [cli_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row kept")
    }

    const ORIGIN: &str = "https://mcp.example.test/mcp";

    #[test]
    fn a_removed_remote_server_loses_its_origin_but_keeps_its_record() {
        let connection = store(&[(
            "local-cli.echo-mcp",
            Some(ORIGIN),
            Some(r#"["codex:remote"]"#),
        )]);
        reconcile(&connection, &["codex"], &[]);
        assert_eq!(row(&connection, "local-cli.echo-mcp"), (None, None));
    }

    #[test]
    fn a_server_still_declared_keeps_its_origin() {
        let connection = store(&[(
            "local-cli.echo-mcp",
            Some(ORIGIN),
            Some(r#"["codex:remote"]"#),
        )]);
        reconcile(&connection, &["codex"], &["local-cli.echo-mcp"]);
        assert_eq!(
            row(&connection, "local-cli.echo-mcp"),
            (
                Some(ORIGIN.to_owned()),
                Some(r#"["codex:remote"]"#.to_owned())
            )
        );
    }

    #[test]
    fn a_harness_the_scan_did_not_read_keeps_its_declaration() {
        let connection = store(&[(
            "local-cli.echo-mcp",
            Some(ORIGIN),
            Some(r#"["codex:remote","cursor:remote"]"#),
        )]);
        reconcile(&connection, &["codex"], &[]);
        assert_eq!(
            row(&connection, "local-cli.echo-mcp"),
            (
                Some(ORIGIN.to_owned()),
                Some(r#"["cursor:remote"]"#.to_owned())
            )
        );
    }

    #[test]
    fn a_stdio_declaration_survives_but_the_origin_goes() {
        let connection = store(&[(
            "local-cli.echo-mcp",
            Some(ORIGIN),
            Some(r#"["codex:remote","codex:stdio"]"#),
        )]);
        reconcile(&connection, &["codex"], &[]);
        assert_eq!(
            row(&connection, "local-cli.echo-mcp"),
            (None, Some(r#"["codex:stdio"]"#.to_owned()))
        );
    }

    #[test]
    fn an_invalid_harness_is_refused() {
        let connection = store(&[]);
        let args: Map<String, Value> = json!({"harnesses": ["Bad Name"], "declared_cli_ids": []})
            .as_object()
            .cloned()
            .expect("object");
        assert!(reconcile_remote_declarations(&connection, &Args(&args)).is_err());
    }
}
