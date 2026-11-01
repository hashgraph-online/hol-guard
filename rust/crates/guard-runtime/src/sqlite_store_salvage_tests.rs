use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;

const CLOUD_SCHEMA: &str = "
    create table sync_state (state_key text primary key, payload_json text not null, updated_at text not null);
    create table guard_devices (device_key text primary key, installation_id text);
    create table guard_connect_states (state_id text primary key, payload text);
    create table guard_exact_cloud_review_receipts (receipt_id text primary key, payload text);
    create table approval_requests (
        request_id text primary key,
        status text not null,
        resolution_action text,
        resolution_scope text,
        artifact_label text
    );
    create table guard_review_outbox_events (event_id text primary key, payload text);
    create table guard_review_outbox_cursors (cursor_id text primary key, position integer);
    create table guard_review_outbox_request_sequences (request_id text primary key, sequence integer);
";

const LOCAL_CLI_SCHEMA: &str = "
    create table local_cli_authority (cli_id text primary key, revision integer);
    create table local_cli_observation (cli_id text primary key, surface text);
    create table local_cli_grant (cli_id text primary key, state text not null);
    create table local_cli_command (cli_id text, command_id text, primary key (cli_id, command_id));
    create table local_cli_command_grant (
        cli_id text,
        command_id text,
        state text not null,
        primary key (cli_id, command_id)
    );
    create table local_cli_grant_capability (cli_id text primary key, capability text);
";

struct Stores {
    _directory: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
}

fn stores(source_schema: &str, destination_schema: &str) -> Stores {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("quarantined.db");
    let destination = directory.path().join("guard.db");
    open(&source)
        .execute_batch(source_schema)
        .expect("source schema");
    open(&destination)
        .execute_batch(destination_schema)
        .expect("destination schema");
    Stores {
        _directory: directory,
        source,
        destination,
    }
}

fn open(path: &Path) -> Connection {
    Connection::open(path).expect("open")
}

fn execute(path: &Path, sql: &str) {
    open(path).execute_batch(sql).expect("execute");
}

fn count(path: &Path, sql: &str) -> i64 {
    open(path)
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn state(path: &Path, key: &str) -> Option<String> {
    open(path)
        .query_row(
            "select payload_json from sync_state where state_key = ?",
            [key],
            |row| row.get(0),
        )
        .optional()
        .expect("state")
}

fn put_state(path: &Path, key: &str, payload: &str) {
    open(path)
        .execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, 't')",
            [key, payload],
        )
        .expect("state insert");
}

fn cloud_source(stores: &Stores) {
    put_state(
        &stores.source,
        "oauth_local_credentials",
        "{\"token\":\"x\"}",
    );
    put_state(
        &stores.source,
        "guard_exact_cloud_review_revocation",
        "{\"revoked\":[]}",
    );
    execute(
        &stores.source,
        "insert into guard_devices values ('local-device', 'install-1');
         insert into approval_requests values ('req-1', 'resolved', 'allow', 'artifact', 'label');
         insert into guard_review_outbox_events values ('event-1', 'payload');",
    );
    execute(
        &stores.destination,
        "insert into guard_devices values ('local-device', 'replacement');",
    );
}

fn receipt(request_id: &str) -> Value {
    let mut receipt = json!({
        "status": "verified",
        "replayed": false,
        "decision": "allow",
        "request_id": request_id,
    });
    for name in RECEIPT_DIGESTS {
        receipt[name] = Value::from("a".repeat(64));
    }
    receipt
}

#[test]
fn cloud_review_state_is_copied_with_canonical_receipts() {
    let stores = stores(CLOUD_SCHEMA, CLOUD_SCHEMA);
    cloud_source(&stores);
    let spaced = serde_json::to_string_pretty(&receipt("req-1")).expect("receipt");
    put_state(
        &stores.source,
        "native_workspace_review.receipt:req-1",
        &spaced,
    );
    put_state(
        &stores.source,
        "review_policy_attribution:req-1",
        "{ \"rule\": \"r\" }",
    );
    put_state(&stores.source, "review_policy_attribution:req-2", "[1]");

    assert!(salvage_cloud_review(&stores.source, &stores.destination));

    assert_eq!(
        state(&stores.destination, "oauth_local_credentials").as_deref(),
        Some("{\"token\":\"x\"}")
    );
    let stored = state(&stores.destination, "native_workspace_review.receipt:req-1")
        .expect("receipt restored");
    assert_eq!(Some(stored), dumps_sorted(&receipt("req-1")));
    assert_eq!(
        state(&stores.destination, "review_policy_attribution:req-1").as_deref(),
        Some("{ \"rule\": \"r\" }")
    );
    assert_eq!(
        state(&stores.destination, "review_policy_attribution:req-2"),
        None
    );
    assert_eq!(
        open(&stores.destination)
            .query_row(
                "select installation_id from guard_devices where device_key = 'local-device'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("device"),
        "install-1"
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from guard_review_outbox_events"
        ),
        1
    );
}

#[test]
fn receipts_that_do_not_bind_their_request_are_skipped() {
    let stores = stores(CLOUD_SCHEMA, CLOUD_SCHEMA);
    cloud_source(&stores);
    execute(
        &stores.source,
        "insert into approval_requests values ('req-pending', 'pending', 'allow', 'artifact', null);
         insert into approval_requests values ('req-block', 'resolved', 'block', 'artifact', null);",
    );
    let mut short_digest = receipt("req-1");
    short_digest["claim_id"] = Value::from("abc");
    put_state(
        &stores.source,
        "native_workspace_review.receipt:req-1",
        &short_digest.to_string(),
    );
    put_state(
        &stores.source,
        "native_workspace_review.receipt:req-pending",
        &receipt("req-pending").to_string(),
    );
    // A blocked request needs a deny receipt.
    put_state(
        &stores.source,
        "native_workspace_review.receipt:req-block",
        &receipt("req-block").to_string(),
    );
    put_state(
        &stores.source,
        "native_workspace_review.receipt:req/../x",
        &receipt("req/../x").to_string(),
    );
    // LIKE reads `_` as a wildcard and ignores case.
    put_state(
        &stores.source,
        "NATIVE_workspace-review.receipt:req-1",
        &receipt("req-1").to_string(),
    );

    assert!(salvage_cloud_review(&stores.source, &stores.destination));

    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from sync_state where state_key like '%receipt%'"
        ),
        0
    );
}

#[test]
fn receipt_payload_requires_the_matching_decision_and_replay_flag() {
    let mut denied = receipt("req-1");
    denied["decision"] = Value::from("deny");
    assert!(receipt_payload(&denied, "req-1", "block").is_some());
    assert!(receipt_payload(&denied, "req-1", "allow").is_none());
    assert!(receipt_payload(&receipt("req-1"), "req-2", "allow").is_none());

    let mut replayed = receipt("req-1");
    replayed["status"] = Value::from("replayed");
    assert!(receipt_payload(&replayed, "req-1", "allow").is_none());
    replayed["replayed"] = Value::Bool(true);
    assert!(receipt_payload(&replayed, "req-1", "allow").is_some());

    let mut upper = receipt("req-1");
    upper["envelope_digest"] = Value::from("A".repeat(64));
    assert!(receipt_payload(&upper, "req-1", "allow").is_none());
}

#[test]
fn a_destination_with_cloud_review_state_is_never_overwritten() {
    let stores = stores(CLOUD_SCHEMA, CLOUD_SCHEMA);
    cloud_source(&stores);
    put_state(
        &stores.destination,
        "guard_exact_cloud_review_capability",
        "{}",
    );

    assert!(!salvage_cloud_review(&stores.source, &stores.destination));
    assert_eq!(state(&stores.destination, "oauth_local_credentials"), None);
}

#[test]
fn credentials_and_the_installation_are_both_required() {
    let without_credentials = stores(CLOUD_SCHEMA, CLOUD_SCHEMA);
    cloud_source(&without_credentials);
    execute(
        &without_credentials.source,
        "delete from sync_state where state_key = 'oauth_local_credentials'",
    );
    assert!(!salvage_cloud_review(
        &without_credentials.source,
        &without_credentials.destination
    ));

    let without_installation = stores(CLOUD_SCHEMA, CLOUD_SCHEMA);
    cloud_source(&without_installation);
    execute(
        &without_installation.source,
        "update guard_devices set installation_id = '' where device_key = 'local-device'",
    );
    assert!(!salvage_cloud_review(
        &without_installation.source,
        &without_installation.destination
    ));
    assert_eq!(
        count(
            &without_installation.destination,
            "select count(*) from sync_state"
        ),
        0
    );
}

#[test]
fn a_source_missing_a_required_column_restores_nothing() {
    let older = CLOUD_SCHEMA.replace(
        "create table guard_review_outbox_cursors (cursor_id text primary key, position integer);",
        "create table guard_review_outbox_cursors (cursor_id text primary key);",
    );
    let stores = stores(&older, CLOUD_SCHEMA);
    cloud_source(&stores);

    assert!(!salvage_cloud_review(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from sync_state"),
        0
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from approval_requests"
        ),
        0
    );
}

#[test]
fn an_older_request_table_may_lack_presentation_columns() {
    let older = CLOUD_SCHEMA.replace(",\n        artifact_label text\n", "\n");
    assert!(!older.contains("artifact_label"));
    let stores = stores(&older, CLOUD_SCHEMA);
    put_state(&stores.source, "oauth_local_credentials", "{}");
    execute(
        &stores.source,
        "insert into guard_devices values ('local-device', 'install-1');
         insert into approval_requests values ('req-1', 'resolved', 'allow', 'artifact');",
    );

    assert!(salvage_cloud_review(&stores.source, &stores.destination));
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from approval_requests where artifact_label is null"
        ),
        1
    );
}

#[test]
fn a_failed_row_rolls_back_every_cloud_review_table() {
    let stricter = CLOUD_SCHEMA.replace(
        "create table guard_review_outbox_events (event_id text primary key, payload text);",
        "create table guard_review_outbox_events (event_id text primary key, \
         payload text check (payload <> 'rejected'));",
    );
    let stores = stores(CLOUD_SCHEMA, &stricter);
    cloud_source(&stores);
    execute(
        &stores.source,
        "insert into guard_review_outbox_events values ('event-2', 'rejected');",
    );

    assert!(!salvage_cloud_review(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from sync_state"),
        0
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from approval_requests"
        ),
        0
    );
    assert_eq!(
        open(&stores.destination)
            .query_row("select installation_id from guard_devices", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("device"),
        "replacement"
    );
}

fn local_cli_source(stores: &Stores) {
    execute(
        &stores.source,
        "insert into local_cli_authority values ('cli-1', 3);
         insert into local_cli_observation values ('cli-1', 'cli');
         insert into local_cli_grant values ('cli-1', 'allowed');
         insert into local_cli_command values ('cli-1', 'navigate');
         insert into local_cli_command values ('cli-1', 'other');
         insert into local_cli_command_grant values ('cli-1', 'navigate', 'block');
         insert into local_cli_command_grant values ('cli-1', 'other', 'block');
         insert into local_cli_grant_capability values ('cli-1', 'cap');",
    );
}

#[test]
fn custom_extension_grants_copy_with_their_catalog() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);

    assert!(salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_grant where state = 'allowed'"
        ),
        1
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_command_grant"
        ),
        2
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_grant_capability"
        ),
        1
    );
}

#[test]
fn a_missing_required_table_restores_no_grant() {
    for table in REQUIRED_LOCAL_CLI_TABLES {
        let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
        local_cli_source(&stores);
        execute(&stores.source, &format!("drop table {table}"));

        assert!(
            !salvage_local_cli(&stores.source, &stores.destination),
            "{table}"
        );
        assert_eq!(
            count(&stores.destination, "select count(*) from local_cli_grant"),
            0
        );
        assert_eq!(
            count(
                &stores.destination,
                "select count(*) from local_cli_command"
            ),
            0
        );
    }
}

#[test]
fn a_command_grant_insert_error_restores_no_grant() {
    let stricter = LOCAL_CLI_SCHEMA.replace(
        "state text not null,\n        primary key (cli_id, command_id)",
        "state text not null check (command_id <> 'other'),\n        primary key (cli_id, command_id)",
    );
    assert_ne!(stricter, LOCAL_CLI_SCHEMA);
    let stores = stores(LOCAL_CLI_SCHEMA, &stricter);
    local_cli_source(&stores);

    assert!(!salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        0
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_command_grant"
        ),
        0
    );
}

/// A source "table" that is a view whose second row fails to read, as a
/// damaged page does part way through a scan.
fn failing_after_first_row(table: &str, columns: &str) -> String {
    format!(
        "alter table {table} rename to {table}_rows;
         create view {table} as select {columns} from {table}_rows
         where case when rowid > 1 then abs(-9223372036854775808) else 1 end;"
    )
}

#[test]
fn a_partial_grant_scan_keeps_the_rows_read_before_the_failure() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(
        &stores.source,
        "insert into local_cli_grant values ('cli-2', 'allowed');",
    );
    execute(
        &stores.source,
        &failing_after_first_row("local_cli_grant", "cli_id, state"),
    );
    let src = Connection::open(&stores.source).expect("source");
    let dst = Connection::open(&stores.destination).expect("destination");

    assert!(copy_allowlisted_table(&src, &dst, "local_cli_grant"));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        1
    );
}

#[test]
fn a_partial_command_grant_scan_restores_no_grant() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(
        &stores.source,
        &failing_after_first_row("local_cli_command_grant", "cli_id, command_id, state"),
    );

    assert!(!salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        0
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_command_grant"
        ),
        0
    );
}

#[test]
fn a_capability_without_its_cli_observation_is_dropped() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(
        &stores.source,
        "update local_cli_observation set surface = 'mcp'",
    );

    assert!(salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        1
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_grant_capability"
        ),
        0
    );
}

#[cfg(unix)]
#[test]
fn linked_stores_are_refused() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    let linked = stores.destination.with_file_name("linked.db");
    std::os::unix::fs::symlink(&stores.source, &linked).expect("symlink");

    assert!(!salvage_local_cli(&linked, &stores.destination));
    assert!(!salvage_local_cli(&stores.source, &linked));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        0
    );
}

#[test]
fn an_unreadable_quarantine_salvages_nothing() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    std::fs::write(&stores.source, b"not-a-sqlite-database").expect("junk");

    assert!(!salvage_local_cli(&stores.source, &stores.destination));
    assert!(!salvage_cloud_review(&stores.source, &stores.destination));
}

#[test]
fn requests_must_name_absolute_stores() {
    let relative = br#"{"schema":"sqlite-store-salvage.v1","source":"a.db","destination":"/b.db"}"#;
    assert_eq!(
        run_command(&relative[..]).expect_err("relative"),
        "sqlite_store_salvage_request_invalid"
    );
    let extra = br#"{"schema":"sqlite-store-salvage.v1","source":"/a","destination":"/b","x":1}"#;
    assert_eq!(
        run_command(&extra[..]).expect_err("unknown field"),
        "sqlite_store_salvage_request_invalid"
    );
    let missing = br#"{"schema":"sqlite-store-salvage.v1","source":"/nonexistent/a.db","destination":"/nonexistent/b.db"}"#;
    let answer: Value =
        serde_json::from_slice(&run_command(&missing[..]).expect("answer")).expect("json");
    assert_eq!(answer, json!({"cloud_review": false, "local_cli": false}));
}
