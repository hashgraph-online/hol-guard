//! Direct tests for the local CLI grant writer. The Python suites drive the
//! whole continuity apply through the native store; these pin the refusals
//! and the rows a write leaves behind.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{apply_continuity, upsert_grant};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, text, StoreError, StoreResult};

const CLI: &str = "local-cli.demo";
const IDENTITY: &str = "identity-one";
const NOW: &str = "2026-11-05T00:00:00+00:00";

fn database(surface: &str) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table local_cli_observation (
                cli_id text primary key,
                identity_hash text not null,
                kind text not null default 'binary',
                name text not null default 'demo',
                interpreter_name text,
                example_label text not null default 'demo',
                observed_count integer not null default 1,
                surface text not null default 'cli',
                server_command text,
                first_blocked_cause text
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
            create table local_cli_grant_capability (
                cli_id text not null,
                capability text not null,
                state text not null,
                revision integer not null,
                updated_at text not null,
                primary key (cli_id, capability)
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
                revision integer not null,
                updated_at text not null
            );
            create table local_mcp_provider_action (
                cli_id text not null, identity_hash text not null, tool_slug text not null,
                revision integer not null,
                primary key (cli_id, identity_hash, tool_slug)
            );
            create table local_mcp_provider_grant (
                cli_id text not null, identity_hash text not null, tool_slug text not null,
                state text not null, updated_at text not null,
                primary key (cli_id, identity_hash, tool_slug)
            );
            create table sync_state (
                state_key text primary key, payload_json text not null, updated_at text not null
            );
            create table guard_events (
                id integer primary key, event_name text not null,
                payload_json text not null, occurred_at text not null
            );",
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_observation (cli_id, identity_hash, surface) values (?, ?, ?)",
            (CLI, IDENTITY, surface),
        )
        .unwrap();
    for (index, command_id) in ["root", "deploy", "other"].iter().enumerate() {
        connection
            .execute(
                "insert into local_cli_command values (?, ?, ?, '', '', null, ?)",
                (CLI, command_id, command_id, index as i64),
            )
            .unwrap();
    }
    connection
}

fn call(
    connection: &Connection,
    write: fn(&Connection, &Args<'_>) -> StoreResult<Value>,
    args: Value,
) -> StoreResult<Value> {
    let args: Map<String, Value> = args.as_object().unwrap().clone();
    write(connection, &Args(&args))
}

fn refusal(result: StoreResult<Value>) -> String {
    match result {
        Err(StoreError::Value(message)) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn continuity(extra: Value) -> Value {
    let mut args = json!({
        "expected_revision": 0,
        "updated_at": NOW,
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "command_states": {"deploy": "block"}}],
        "sync_payloads": {"custom_extension_continuity": "{\"v\": 1}"},
        "events": [["custom_extension_continuity_applied", "{\"n\": 1}"]],
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    args
}

fn count(connection: &Connection, sql: &str) -> usize {
    query_all(connection, sql, &[]).unwrap().len()
}

#[test]
fn a_continuity_apply_writes_authority_state_and_receipt_together() {
    let connection = database("cli");
    let revision = call(&connection, apply_continuity, continuity(json!({}))).unwrap();
    assert_eq!(revision, json!(1));
    let grant = query_one(&connection, "select * from local_cli_grant", &[])
        .unwrap()
        .unwrap();
    assert_eq!(text(&grant, "state"), "allowed");
    assert_eq!(grant["revision"], json!(1));
    let command = query_one(&connection, "select * from local_cli_command_grant", &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        (text(&command, "command_id"), text(&command, "state")),
        ("deploy", "block")
    );
    let state = query_one(&connection, "select payload_json from sync_state", &[])
        .unwrap()
        .unwrap();
    assert_eq!(text(&state, "payload_json"), "{\"v\": 1}");
    let event = query_one(&connection, "select * from guard_events", &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        text(&event, "event_name"),
        "custom_extension_continuity_applied"
    );
    let authority = query_one(&connection, "select revision from local_cli_authority", &[])
        .unwrap()
        .unwrap();
    assert_eq!(authority["revision"], json!(1));
}

#[test]
fn a_stale_revision_or_changed_precondition_writes_nothing() {
    let connection = database("cli");
    for (extra, message) in [
        (
            json!({"expected_revision": 3}),
            "local_cli_revision_conflict",
        ),
        (
            json!({"sync_preconditions": {"custom_extension_continuity": {"v": 0}}}),
            "custom_extension_continuity_sync_precondition_changed",
        ),
        (
            json!({"observation_preconditions": {CLI: null}}),
            "custom_extension_continuity_observation_changed",
        ),
        (
            json!({"provider_updates": {"local-cli.other": []}}),
            "provider choices require matching extension authority",
        ),
        (
            json!({"capability_updates": {"local-cli.other": {}}}),
            "capability choices require matching extension authority",
        ),
    ] {
        assert_eq!(
            refusal(call(&connection, apply_continuity, continuity(extra))),
            message
        );
    }
    assert_eq!(count(&connection, "select * from local_cli_grant"), 0);
    assert_eq!(count(&connection, "select * from sync_state"), 0);
}

#[test]
fn the_observation_precondition_matches_the_stored_snapshot() {
    let connection = database("cli");
    let snapshot = json!({
        "identity_hash": IDENTITY, "kind": "binary", "name": "demo",
        "interpreter_name": null, "example_label": "demo", "observed_count": 1,
        "surface": "cli", "command_ids": ["root", "deploy", "other"],
    });
    let extra = json!({"observation_preconditions": {CLI: snapshot}});
    assert_eq!(
        call(&connection, apply_continuity, continuity(extra)).unwrap(),
        json!(1)
    );
}

#[test]
fn invalid_updates_are_refused_by_name() {
    let connection = database("cli");
    let bad_state = json!({"updates": [{"cli_id": CLI, "identity_hash": IDENTITY,
        "state": "maybe", "command_states": null}]});
    assert_eq!(
        refusal(call(&connection, apply_continuity, continuity(bad_state))),
        "invalid local CLI continuity update"
    );
    let bad_command = json!({"updates": [{"cli_id": CLI, "identity_hash": IDENTITY,
        "state": "allowed", "command_states": {"deploy": "sometimes"}}]});
    assert_eq!(
        refusal(call(&connection, apply_continuity, continuity(bad_command))),
        "invalid local CLI continuity command update"
    );
    let review_on_cli = json!({"updates": [{"cli_id": CLI, "identity_hash": IDENTITY,
        "state": "allowed", "command_states": {"deploy": "review"}}]});
    assert_eq!(
        refusal(call(
            &connection,
            apply_continuity,
            continuity(review_on_cli)
        )),
        "explicit review is supported only for MCP tools"
    );
    let unset_capabilities = json!({
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "unset",
            "command_states": null}],
        "capability_updates": {CLI: {"loopback-network": "on"}},
    });
    assert_eq!(
        refusal(call(
            &connection,
            apply_continuity,
            continuity(unset_capabilities)
        )),
        "capabilities_require_allowed_grant"
    );
}

#[test]
fn capabilities_follow_the_allowed_grant_and_clear_their_blocked_cause() {
    let connection = database("cli");
    connection
        .execute(
            "update local_cli_observation set first_blocked_cause = 'connect_loopback'",
            [],
        )
        .unwrap();
    let extra =
        json!({"capability_updates": {CLI: {"loopback-network": "on", "state-dir-read": "off"}}});
    call(&connection, apply_continuity, continuity(extra)).unwrap();
    let rows = query_all(
        &connection,
        "select capability, state from local_cli_grant_capability order by capability",
        &[],
    )
    .unwrap();
    let rows: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (text(row, "capability"), text(row, "state")))
        .collect();
    assert_eq!(
        rows,
        [("loopback-network", "on"), ("state-dir-read", "off")]
    );
    let cause = query_one(
        &connection,
        "select first_blocked_cause from local_cli_observation",
        &[],
    )
    .unwrap()
    .unwrap();
    assert_eq!(cause["first_blocked_cause"], Value::Null);

    // Blocking the grant drops the capabilities chosen for the allowed one.
    let blocked = json!({"expected_revision": 1, "updates": [{"cli_id": CLI,
        "identity_hash": IDENTITY, "state": "blocked", "command_states": null}]});
    call(&connection, apply_continuity, continuity(blocked)).unwrap();
    assert_eq!(
        count(&connection, "select * from local_cli_grant_capability"),
        0
    );
}

#[test]
fn a_default_catalog_is_seeded_and_a_curated_one_is_kept() {
    let connection = database("cli");
    connection
        .execute(
            "delete from local_cli_command where command_id = 'deploy'",
            [],
        )
        .unwrap();
    let seed = json!([
        {"command_id": "root", "name": "demo", "usage": "", "description": ""},
        {"command_id": "build", "name": "build", "usage": "", "description": ""},
        {"command_id": "other", "name": "other", "usage": "", "description": ""},
    ]);
    let extra = json!({"catalog_seeds": {CLI: seed},
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "command_states": {"build": "allow"}}]});
    call(&connection, apply_continuity, continuity(extra)).unwrap();
    let ids: Vec<String> = query_all(
        &connection,
        "select command_id from local_cli_command order by sort_index",
        &[],
    )
    .unwrap()
    .iter()
    .map(|row| text(row, "command_id").to_owned())
    .collect();
    assert_eq!(ids, ["root", "build", "other"]);

    let missing_other = json!({"expected_revision": 1, "catalog_seeds": {CLI: [
        {"command_id": "root", "name": "demo", "usage": "", "description": ""}]},
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "command_states": null}]});
    // A curated catalog is never replaced, so even a bad seed is skipped.
    call(&connection, apply_continuity, continuity(missing_other)).unwrap();
}

#[test]
fn an_mcp_save_acknowledges_the_reviewed_changes_and_keeps_tombstones() {
    let connection = database("mcp");
    connection
        .execute(
            "insert into local_cli_command_grant values (?, 'retired', 'block')",
            [CLI],
        )
        .unwrap();
    connection
        .execute(
            "insert into local_mcp_catalog values (?, ?, ?, 4, ?)",
            (
                CLI,
                IDENTITY,
                r#"{"changes":{"added":["deploy","fresh"],"changed":["root"]},"complete":true,"tools":[]}"#,
                NOW,
            ),
        )
        .unwrap();
    let revision = call(
        &connection,
        upsert_grant,
        json!({"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "expected_revision": 0, "updated_at": NOW,
            "command_states": {"deploy": "review"},
            "reviewed_catalog_revision": 4,
            "catalog_change_ids": {"deploy": "deploy", "fresh": "fresh", "root": "root"}}),
    )
    .unwrap();
    assert_eq!(revision, json!(1));
    let catalog = query_one(
        &connection,
        "select catalog_json from local_mcp_catalog",
        &[],
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        text(&catalog, "catalog_json"),
        r#"{"changes":{"added":["fresh"],"changed":["root"]},"complete":true,"tools":[]}"#
    );
    let grants: Vec<String> = query_all(
        &connection,
        "select command_id || ':' || state as row from local_cli_command_grant order by command_id",
        &[],
    )
    .unwrap()
    .iter()
    .map(|row| text(row, "row").to_owned())
    .collect();
    assert_eq!(grants, ["deploy:review", "retired:block"]);
}

#[test]
fn removing_a_grant_drops_every_choice_made_for_it() {
    let connection = database("cli");
    call(&connection, apply_continuity, continuity(json!({}))).unwrap();
    let revision = call(
        &connection,
        upsert_grant,
        json!({"cli_id": CLI, "identity_hash": IDENTITY, "state": "unset",
            "expected_revision": 1, "updated_at": NOW}),
    )
    .unwrap();
    assert_eq!(revision, json!(2));
    assert_eq!(count(&connection, "select * from local_cli_grant"), 0);
    assert_eq!(
        count(&connection, "select * from local_cli_command_grant"),
        0
    );
    assert_eq!(
        refusal(call(
            &connection,
            upsert_grant,
            json!({"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
                "expected_revision": 1, "updated_at": NOW}),
        )),
        "local_cli_revision_conflict"
    );
    assert_eq!(
        refusal(call(
            &connection,
            upsert_grant,
            json!({"cli_id": "not-a-cli", "identity_hash": IDENTITY, "state": "allowed",
                "expected_revision": 2, "updated_at": NOW}),
        )),
        "invalid local CLI id"
    );
}

#[test]
fn provider_choices_need_a_current_action_on_an_mcp_connector() {
    let connection = database("mcp");
    connection
        .execute(
            "insert into local_mcp_provider_action values (?, ?, 'send', 2)",
            (CLI, IDENTITY),
        )
        .unwrap();
    let stale = json!({"provider_updates": {CLI: [["send", "block", 1]]},
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "command_states": null}]});
    assert_eq!(
        refusal(call(&connection, apply_continuity, continuity(stale))),
        "provider_action_revision_conflict"
    );
    let unmarked = json!({"provider_updates": {CLI: [["send", "block", 2]]},
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "command_states": null}]});
    assert_eq!(
        refusal(call(&connection, apply_continuity, continuity(unmarked))),
        "invalid provider authority identity"
    );
    let invalid = json!({"provider_updates": {CLI: [["send", "allow", 2]]},
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "allowed",
            "command_states": null}]});
    assert_eq!(
        refusal(call(&connection, apply_continuity, continuity(invalid))),
        "invalid provider action choice"
    );
    let removal = json!({"provider_updates": {CLI: [["send", "block", 2]]},
        "updates": [{"cli_id": CLI, "identity_hash": IDENTITY, "state": "unset",
            "command_states": null}]});
    assert_eq!(
        refusal(call(&connection, apply_continuity, continuity(removal))),
        "provider choices cannot accompany removal"
    );
}
