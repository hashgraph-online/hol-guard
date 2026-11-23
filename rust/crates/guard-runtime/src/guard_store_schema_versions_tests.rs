use rusqlite::{params, Connection};

use super::{
    create_approval_indexes, create_base, ensure_local_device, record_version,
    reopen_expired_approvals, request_rollup_rebuilds, upgrade_approval_requests,
    upgrade_receipt_envelopes,
};

const NOW: &str = "2026-01-02T03:04:05.000006+00:00";
const LATER: &str = "2026-02-02T03:04:05.000006+00:00";

fn count(connection: &Connection, sql: &str) -> i64 {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn text(connection: &Connection, sql: &str) -> String {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("text")
}

#[test]
fn a_legacy_inline_envelope_moves_to_its_own_table_once() {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table schema_migrations (version integer primary key, applied_at text not null);
             create table runtime_receipts (receipt_id text primary key, harness text not null,
               artifact_id text not null, artifact_hash text not null, policy_decision text not null,
               capabilities_summary text not null default '', changed_capabilities_json text not null,
               provenance_summary text not null, user_override text, artifact_name text,
               source_scope text, scanner_evidence_json text not null default '[]',
               timestamp text not null, diff_summary text, approval_source text,
               action_envelope_json text);
             insert into runtime_receipts (receipt_id, harness, artifact_id, artifact_hash,
               policy_decision, changed_capabilities_json, provenance_summary, timestamp,
               action_envelope_json)
             values ('r1', 'codex', 'a', 'h', 'allow', '[]', 'p', 't', '{\"k\":1}');",
        )
        .expect("legacy");
    upgrade_receipt_envelopes(&connection, NOW).expect("upgrade");
    assert_eq!(
        text(
            &connection,
            "select envelope_full_json from runtime_receipt_envelopes"
        ),
        "{\"k\":1}"
    );
    assert_eq!(
        count(
            &connection,
            "select count(*) from pragma_table_info('runtime_receipts') \
             where name = 'action_envelope_json'"
        ),
        0
    );
    assert_eq!(
        count(&connection, "select count(*) from runtime_receipts"),
        1
    );
    upgrade_receipt_envelopes(&connection, LATER).expect("again");
    assert_eq!(
        text(
            &connection,
            "select applied_at from schema_migrations where version = 5"
        ),
        NOW
    );
}

#[test]
fn rollup_rebuilds_are_requested_once_per_version() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    connection
        .execute("delete from schema_migrations where version in (6, 16)", [])
        .expect("forget");
    request_rollup_rebuilds(&connection, NOW).expect("first");
    assert_eq!(
        text(
            &connection,
            "select updated_at from sync_state where state_key = 'receipt_rollups_rebuild_pending'"
        ),
        NOW
    );
    connection
        .execute("delete from sync_state", [])
        .expect("drained");
    request_rollup_rebuilds(&connection, LATER).expect("second");
    assert_eq!(count(&connection, "select count(*) from sync_state"), 0);
}

#[test]
fn the_local_device_is_inserted_once() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_local_device(&connection, "first-id", NOW).expect("first");
    ensure_local_device(&connection, "second-id", LATER).expect("second");
    assert_eq!(
        text(
            &connection,
            "select installation_id || '|' || device_label || '|' || created_at \
             from guard_devices where device_key = 'local-device'"
        ),
        format!("first-id|Local machine|{NOW}")
    );
}

#[test]
fn record_version_keeps_the_first_timestamp() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    record_version(&connection, 990, NOW).expect("first");
    record_version(&connection, 990, LATER).expect("second");
    assert_eq!(
        text(
            &connection,
            "select applied_at from schema_migrations where version = 990"
        ),
        NOW
    );
}

fn insert_approval(connection: &Connection, request_id: &str, status: &str, reason: &str) {
    connection
        .execute(
            "insert into approval_requests (request_id, harness, artifact_id, artifact_name, \
               artifact_type, artifact_hash, policy_action, recommended_scope, \
               changed_fields_json, source_scope, config_path, review_command, approval_url, \
               status, reason, created_at, resolved_at) \
             values (?1, 'codex', 'a', 'a', 'artifact', 'h', 'require-reapproval', 'artifact', \
               '[]', 'project', 'c', 'r', 'u', ?2, ?3, ?4, ?4)",
            params![request_id, status, reason, NOW],
        )
        .expect("insert");
}

#[test]
fn only_legacy_wait_timeouts_are_reopened() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    insert_approval(
        &connection,
        "legacy",
        "expired",
        "Expired after waiting for review.",
    );
    insert_approval(
        &connection,
        "superseded",
        "expired",
        "Superseded by a newer request.",
    );
    reopen_expired_approvals(&connection).expect("reopen");
    assert_eq!(
        text(
            &connection,
            "select status || '|' || coalesce(reason, '') || '|' || coalesce(resolved_at, '') \
             from approval_requests where request_id = 'legacy'"
        ),
        "pending||"
    );
    assert_eq!(
        text(
            &connection,
            "select status from approval_requests where request_id = 'superseded'"
        ),
        "expired"
    );
}

#[test]
fn a_store_before_version_nine_drops_the_retired_group_index() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    upgrade_approval_requests(&connection).expect("columns");
    connection
        .execute("delete from schema_migrations where version = 9", [])
        .expect("forget");
    connection
        .execute_batch("create index idx_approval_group_status on approval_requests (status)")
        .expect("retired index");
    create_approval_indexes(&connection).expect("indexes");
    assert_eq!(
        count(
            &connection,
            "select count(*) from sqlite_master where name = 'idx_approval_group_status' \
             and sql like '%(status)'"
        ),
        0
    );
}
