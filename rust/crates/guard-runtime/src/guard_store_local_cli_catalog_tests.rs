//! Direct tests for the local CLI command catalog and the MCP snapshot it
//! carries. The vectors suites replay whole recorded sessions; these cover the
//! decisions a vector would only reach by accident — an incomplete page, a
//! name that already holds a Deny, a naive cache timestamp.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::write_local_cli_catalog;
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, text, StoreError, StoreResult};
use crate::guard_store_local_cli_mcp_snapshot::{fresh_until, iso_date};

const CLI: &str = "local-cli.demo";
const IDENTITY: &str = "identity-one";

fn database() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table local_cli_observation (
                cli_id text primary key,
                identity_hash text not null,
                surface text not null default 'cli'
            );
            create table local_cli_command (
                cli_id text not null,
                command_id text not null,
                name text not null,
                usage text not null,
                description text not null,
                parent_id text,
                sort_index integer not null check (sort_index >= 0),
                primary key (cli_id, command_id)
            );
            create table local_cli_command_grant (
                cli_id text not null,
                command_id text not null,
                state text not null check (state in ('inherit', 'allow', 'review', 'block')),
                primary key (cli_id, command_id)
            );
            create table local_cli_grant (
                cli_id text primary key,
                identity_hash text not null,
                state text not null,
                revision integer not null,
                updated_at text not null
            );
            create table local_cli_authority (
                singleton integer primary key check (singleton = 1),
                revision integer not null check (revision >= 0)
            );
            insert into local_cli_authority (singleton, revision) values (1, 0);
            create table local_mcp_catalog (
                cli_id text primary key,
                identity_hash text not null,
                catalog_json text not null,
                revision integer not null check (revision >= 1),
                updated_at text not null,
                last_complete_at text
            );
            create table local_mcp_tool_authority (
                cli_id text not null, identity_hash text not null, tool_name text not null,
                catalog_revision integer not null, authority_hash text not null,
                primary key (cli_id, identity_hash, tool_name)
            );",
        )
        .unwrap();
    connection
}

fn observed(connection: &Connection, surface: &str) {
    connection
        .execute(
            "insert into local_cli_observation (cli_id, identity_hash, surface) values (?, ?, ?)",
            (CLI, IDENTITY, surface),
        )
        .unwrap();
}

fn command(command_id: &str, name: &str) -> Value {
    json!({
        "command_id": command_id,
        "name": name,
        "usage": format!("{name} [options]"),
        "description": "",
    })
}

fn tool(name: &str, extra: Value) -> Value {
    json!({"name": name, "inputSchema": {"type": "object", "properties": extra}})
}

fn call(connection: &Connection, args: Value, merging: bool) -> StoreResult<Value> {
    let args = args.as_object().unwrap().clone();
    write_local_cli_catalog(connection, &Args(&args), merging)
}

fn message(error: StoreError) -> String {
    match error {
        StoreError::Value(message) => message,
        other => panic!("expected a ValueError, got {other:?}"),
    }
}

fn snapshot(connection: &Connection) -> Value {
    let row = query_one(
        connection,
        "select catalog_json from local_mcp_catalog where cli_id = ?",
        &[Value::from(CLI)],
    )
    .unwrap()
    .expect("a stored catalog");
    serde_json::from_str(text(&row, "catalog_json")).unwrap()
}

fn grant_states(connection: &Connection) -> Vec<(String, String)> {
    query_all(
        connection,
        "select command_id, state from local_cli_command_grant \
         where cli_id = ? order by command_id",
        &[Value::from(CLI)],
    )
    .unwrap()
    .iter()
    .map(|row| {
        (
            text(row, "command_id").to_owned(),
            text(row, "state").to_owned(),
        )
    })
    .collect()
}

#[test]
fn replace_rewrites_rows_in_order_and_truncates_text() {
    let connection = database();
    let long = "n".repeat(200);
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [
                command("second", "two"),
                {
                    "command_id": "first",
                    "name": long,
                    "usage": "u".repeat(200),
                    "description": "d".repeat(300),
                    "parent_id": "second",
                },
            ],
        }),
        false,
    )
    .unwrap();
    let rows = query_all(
        &connection,
        "select command_id, name, usage, description, parent_id, sort_index \
         from local_cli_command where cli_id = ? order by sort_index",
        &[Value::from(CLI)],
    )
    .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "command_id"))
            .collect::<Vec<_>>(),
        ["second", "first"],
    );
    assert_eq!(text(&rows[1], "name").len(), 120);
    assert_eq!(text(&rows[1], "usage").len(), 160);
    assert_eq!(text(&rows[1], "description").len(), 240);
    assert_eq!(text(&rows[1], "parent_id"), "second");
}

#[test]
fn replace_without_a_catalog_drops_grants_for_commands_that_are_gone() {
    let connection = database();
    connection
        .execute(
            "insert into local_cli_command_grant (cli_id, command_id, state) values \
             (?, 'retired', 'allow'), (?, 'denied', 'block'), (?, 'kept', 'allow')",
            (CLI, CLI, CLI),
        )
        .unwrap();
    call(
        &connection,
        json!({"cli_id": CLI, "commands": [command("kept", "kept")]}),
        false,
    )
    .unwrap();
    assert_eq!(grant_states(&connection), [("kept".into(), "allow".into())]);
}

#[test]
fn a_catalog_write_keeps_deny_tombstones_for_tools_that_left() {
    let connection = database();
    observed(&connection, "mcp");
    connection
        .execute(
            "insert into local_cli_command_grant (cli_id, command_id, state) values \
             (?, 'retired', 'allow'), (?, 'denied', 'block')",
            (CLI, CLI),
        )
        .unwrap();
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": []},
        }),
        false,
    )
    .unwrap();
    assert_eq!(
        grant_states(&connection),
        [("denied".into(), "block".into())]
    );
}

#[test]
fn merge_appends_without_disturbing_stored_rows() {
    let connection = database();
    call(
        &connection,
        json!({"cli_id": CLI, "commands": [command("first", "one")]}),
        false,
    )
    .unwrap();
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "limit": 8,
            "commands": [command("first", "renamed"), command("second", "two")],
        }),
        true,
    )
    .unwrap();
    let rows = query_all(
        &connection,
        "select command_id, name, sort_index from local_cli_command \
         where cli_id = ? order by sort_index",
        &[Value::from(CLI)],
    )
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(text(&rows[0], "name"), "one");
    assert_eq!(text(&rows[1], "command_id"), "second");
}

#[test]
fn merge_refuses_the_whole_batch_once_the_union_outgrows_the_limit() {
    let connection = database();
    let error = call(
        &connection,
        json!({
            "cli_id": CLI,
            "limit": 1,
            "commands": [command("first", "one"), command("second", "two")],
        }),
        true,
    )
    .unwrap_err();
    assert_eq!(message(error), "local_cli_catalog_limit");
    assert_eq!(
        query_all(
            &connection,
            "select command_id from local_cli_command where cli_id = ?",
            &[Value::from(CLI)],
        )
        .unwrap()
        .len(),
        0,
    );
}

#[test]
fn a_new_tool_moves_to_review_and_gains_an_authority_row() {
    let connection = database();
    observed(&connection, "mcp");
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [command("search", "search")],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {
                "complete": true,
                "tools": [tool("search", json!({}))],
                "cache_ttl_ms": 60_000,
            },
        }),
        false,
    )
    .unwrap();
    assert_eq!(
        grant_states(&connection),
        [("search".into(), "review".into())]
    );
    let authority = query_all(
        &connection,
        "select tool_name, catalog_revision from local_mcp_tool_authority where cli_id = ?",
        &[Value::from(CLI)],
    )
    .unwrap();
    assert_eq!(authority.len(), 1);
    assert_eq!(text(&authority[0], "tool_name"), "search");
    let stored = snapshot(&connection);
    assert_eq!(stored["known_count"], json!(1));
    assert_eq!(stored["changes"]["added"], json!(["search"]));
    assert_eq!(stored["fresh_until"], json!("2026-10-26T00:01:00+00:00"));
}

#[test]
fn a_widened_schema_moves_an_allowed_tool_back_to_review() {
    let connection = database();
    observed(&connection, "mcp");
    let args = |schema: Value| {
        json!({
            "cli_id": CLI,
            "commands": [command("search", "search")],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": [tool("search", schema)]},
        })
    };
    call(&connection, args(json!({})), false).unwrap();
    connection
        .execute(
            "update local_cli_command_grant set state = 'allow' where cli_id = ?",
            (CLI,),
        )
        .unwrap();
    call(
        &connection,
        args(json!({"path": {"type": "string"}})),
        false,
    )
    .unwrap();
    assert_eq!(
        grant_states(&connection),
        [("search".into(), "review".into())]
    );
    assert_eq!(
        snapshot(&connection)["changes"]["changed"],
        json!(["search"])
    );
}

#[test]
fn an_incomplete_page_keeps_what_is_known_and_says_so() {
    let connection = database();
    observed(&connection, "mcp");
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": [tool("search", json!({}))]},
        }),
        false,
    )
    .unwrap();
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:05:00+00:00",
            "mcp_catalog": {"complete": false, "tools": [], "reason": "page_timeout"},
        }),
        false,
    )
    .unwrap();
    let stored = snapshot(&connection);
    assert_eq!(stored["known_count"], json!(1));
    assert_eq!(stored["stale"], json!(true));
    assert_eq!(stored["changes"]["removed"], json!([]));
    assert_eq!(stored["changes"]["stale"], json!(["search"]));
    assert_eq!(stored["fresh_until"], Value::Null);
    let row = query_one(
        &connection,
        "select last_complete_at from local_mcp_catalog where cli_id = ?",
        &[Value::from(CLI)],
    )
    .unwrap()
    .unwrap();
    assert_eq!(text(&row, "last_complete_at"), "2026-10-26T00:00:00+00:00");
}

#[test]
fn a_moved_revision_fails_the_whole_write() {
    let connection = database();
    observed(&connection, "mcp");
    let error = call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [command("search", "search")],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "expected_catalog_revision": 3,
            "mcp_catalog": {"complete": true, "tools": []},
        }),
        false,
    )
    .unwrap_err();
    assert_eq!(message(error), "mcp_catalog_revision_conflict");
    assert_eq!(
        query_all(
            &connection,
            "select command_id from local_cli_command where cli_id = ?",
            &[Value::from(CLI)],
        )
        .unwrap()
        .len(),
        0,
    );
}

#[test]
fn a_catalog_on_a_non_mcp_surface_is_refused() {
    let connection = database();
    observed(&connection, "cli");
    let error = call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": []},
        }),
        false,
    )
    .unwrap_err();
    assert_eq!(
        message(error),
        "MCP catalog identity changed during discovery"
    );
}

#[test]
fn a_catalog_without_an_observation_is_refused() {
    let connection = database();
    let error = call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": []},
        }),
        false,
    )
    .unwrap_err();
    assert_eq!(
        message(error),
        "MCP catalog requires an observed identity and refresh time",
    );
}

#[test]
fn a_padded_tool_name_is_not_an_identity() {
    let connection = database();
    observed(&connection, "mcp");
    let error = call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": [tool(" search", json!({}))]},
        }),
        false,
    )
    .unwrap_err();
    assert_eq!(message(error), "invalid MCP catalog tool identity");
}

#[test]
fn an_unparsable_command_id_is_refused() {
    let connection = database();
    let error = call(
        &connection,
        json!({"cli_id": CLI, "commands": [command("1bad", "bad")]}),
        false,
    )
    .unwrap_err();
    assert_eq!(message(error), "invalid local CLI command id");
}

#[test]
fn a_catalog_that_is_not_an_object_fails_closed() {
    let connection = database();
    let error = call(
        &connection,
        json!({"cli_id": CLI, "commands": [], "mcp_catalog": []}),
        false,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        StoreError::Invalid("native_guard_store_args_invalid"),
    ));
}

#[test]
fn review_moves_the_grant_revision_only_when_the_extension_holds_one() {
    let connection = database();
    observed(&connection, "mcp");
    connection
        .execute(
            "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) \
             values (?, ?, 'allowed', 5, '2026-10-25T00:00:00+00:00')",
            (CLI, IDENTITY),
        )
        .unwrap();
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [command("search", "search")],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {"complete": true, "tools": [tool("search", json!({}))]},
        }),
        false,
    )
    .unwrap();
    let row = query_one(
        &connection,
        "select revision, updated_at from local_cli_grant where cli_id = ?",
        &[Value::from(CLI)],
    )
    .unwrap()
    .unwrap();
    assert_eq!(crate::guard_store_db::int(&row, "revision"), 1);
    assert_eq!(text(&row, "updated_at"), "2026-10-26T00:00:00+00:00");
}

#[test]
fn a_naive_cache_instant_stores_no_freshness_deadline() {
    assert_eq!(
        fresh_until("2026-10-26T00:00:00", Some(&json!(1000))),
        Value::Null,
    );
    assert_eq!(
        fresh_until("2026-10-26T00:00:00Z", Some(&json!(1000))),
        json!("2026-10-26T00:00:01+00:00"),
    );
}

#[test]
fn a_zero_or_boolean_ttl_provides_no_window() {
    let received = "2026-10-26T00:00:00+00:00";
    assert_eq!(fresh_until(received, Some(&json!(0))), Value::Null);
    assert_eq!(fresh_until(received, Some(&json!(true))), Value::Null);
    assert_eq!(fresh_until(received, Some(&json!(86_400_001))), Value::Null);
    assert_eq!(fresh_until(received, None), Value::Null);
}

#[test]
fn a_protocol_version_has_to_name_a_day_that_exists() {
    assert_eq!(iso_date("2026-07-28"), Some((2026, 7, 28)));
    assert_eq!(iso_date("2026-02-30"), None);
    assert_eq!(iso_date("2024-02-29"), Some((2024, 2, 29)));
    assert_eq!(iso_date("2026-02-29"), None);
    assert_eq!(iso_date("2026-7-28"), None);
    assert_eq!(iso_date(""), None);
}

#[test]
fn an_empty_args_map_fails_closed() {
    let connection = database();
    let args: Map<String, Value> = Map::new();
    assert!(write_local_cli_catalog(&connection, &Args(&args), false).is_err());
}

#[test]
fn a_tool_listed_twice_counts_as_one_change() {
    let connection = database();
    observed(&connection, "mcp");
    call(
        &connection,
        json!({
            "cli_id": CLI,
            "commands": [command("search", "search")],
            "identity_hash": IDENTITY,
            "seen_at": "2026-10-26T00:00:00+00:00",
            "mcp_catalog": {
                "complete": true,
                "tools": [tool("search", json!({})), tool("search", json!({}))],
            },
        }),
        false,
    )
    .unwrap();
    let stored = snapshot(&connection);
    assert_eq!(stored["changes"]["added"], json!(["search"]));
    assert_eq!(stored["known_count"], json!(1));
    assert_eq!(
        grant_states(&connection),
        [("search".into(), "review".into())]
    );
}
