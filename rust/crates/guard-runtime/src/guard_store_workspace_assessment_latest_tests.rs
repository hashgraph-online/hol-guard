//! The latest-assessed-runs listing and the feed digest against an in-memory
//! copy of the tables they read.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{dispatch, handles};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_op_kind::{method_kind, Kind};

const SCHEMA: &str = "
create table workspace_assessment_runs (
    run_id text not null primary key, codebase_key text not null, worktree_key text not null,
    snapshot_digest text, kind text not null, trigger_kind text not null, state text not null,
    dirty_generation integer not null, coverage_json text not null default '{}',
    findings_json text not null default '[]', error_code text,
    created_at_ms integer not null, started_at_ms integer, finished_at_ms integer
);
create table guard_supply_chain_bundle_cache (
    workspace_id text primary key, payload_hash text not null, policy_hash text not null
);
";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection.execute_batch(SCHEMA).expect("schema");
    connection
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(map) = args else {
        panic!("args must be an object");
    };
    dispatch(connection, method, &Args(&map))
}

fn run(connection: &Connection, run_id: &str, worktree: &str, state: &str, finished: Option<i64>) {
    connection
        .execute(
            "insert into workspace_assessment_runs (run_id, codebase_key, worktree_key, kind, \
             trigger_kind, state, dirty_generation, findings_json, created_at_ms, finished_at_ms) \
             values (?1, 'cb', ?2, 'full', 'manual', ?3, 1, ?4, 1, ?5)",
            rusqlite::params![run_id, worktree, state, format!("[\"{run_id}\"]"), finished],
        )
        .expect("run");
}

fn run_ids(answer: &Value) -> Vec<&str> {
    answer["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["run_id"].as_str().expect("run id"))
        .collect()
}

#[test]
fn both_methods_route_here_as_reads() {
    for method in [
        "list_latest_assessed_workspace_runs",
        "workspace_assessment_feed_digest",
    ] {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Read)));
    }
}

#[test]
fn each_worktree_lists_its_newest_assessed_run_with_findings() {
    let connection = store();
    run(&connection, "a-old", "wt-a", "completed", Some(10));
    run(&connection, "a-new", "wt-a", "partial", Some(20));
    run(&connection, "a-running", "wt-a", "running", None);
    run(&connection, "b-only", "wt-b", "completed", Some(5));
    run(&connection, "c-failed", "wt-c", "failed", Some(30));

    let answer = call(
        &connection,
        "list_latest_assessed_workspace_runs",
        json!({}),
    )
    .expect("list");

    assert_eq!(run_ids(&answer), ["a-new", "b-only"]);
    assert_eq!(answer["next"], Value::Null);
    assert_eq!(answer["items"][0]["findings_json"], "[\"a-new\"]");
}

#[test]
fn a_tie_on_finish_time_keeps_queue_order() {
    let connection = store();
    run(&connection, "first", "wt-a", "completed", Some(10));
    run(&connection, "second", "wt-a", "completed", Some(10));

    let answer = call(
        &connection,
        "list_latest_assessed_workspace_runs",
        json!({}),
    )
    .expect("list");

    assert_eq!(run_ids(&answer), ["second"]);
}

#[test]
fn keys_limit_the_listing_to_the_named_worktrees() {
    let connection = store();
    run(&connection, "a", "wt-a", "completed", Some(1));
    run(&connection, "b", "wt-b", "completed", Some(1));
    run(&connection, "c", "wt-c", "completed", Some(1));

    let answer = call(
        &connection,
        "list_latest_assessed_workspace_runs",
        json!({"keys": [["cb", "wt-c"], ["cb", "wt-a"], ["other", "wt-b"]]}),
    )
    .expect("list");
    assert_eq!(run_ids(&answer), ["a", "c"]);

    let none = call(
        &connection,
        "list_latest_assessed_workspace_runs",
        json!({"keys": []}),
    )
    .expect("list");
    assert_eq!(run_ids(&none), Vec::<&str>::new());
}

#[test]
fn the_after_cursor_continues_past_the_last_worktree() {
    let connection = store();
    run(&connection, "a", "wt-a", "completed", Some(1));
    run(&connection, "b", "wt-b", "completed", Some(1));

    let answer = call(
        &connection,
        "list_latest_assessed_workspace_runs",
        json!({"after": ["cb", "wt-a"]}),
    )
    .expect("list");

    assert_eq!(run_ids(&answer), ["b"]);
}

#[test]
fn malformed_keys_and_cursors_are_refused() {
    let connection = store();
    for args in [
        json!({"keys": "cb"}),
        json!({"keys": [["cb"]]}),
        json!({"keys": [["cb", 1]]}),
        json!({"keys": [["cb", "wt", "extra"]]}),
        json!({"after": ["cb"]}),
        json!({"after": ["cb", 2]}),
    ] {
        let result = call(&connection, "list_latest_assessed_workspace_runs", args);
        assert!(matches!(result, Err(StoreError::Value(_))));
    }
}

#[test]
fn the_feed_digest_matches_the_python_digest() {
    let connection = store();
    let empty = call(&connection, "workspace_assessment_feed_digest", json!({})).expect("digest");
    assert_eq!(
        empty,
        "8d809e55cf2a9811b5d6d9030d0d274813106dc87af242d9600206802dd2c62a"
    );

    connection
        .execute_batch(
            "insert into guard_supply_chain_bundle_cache values ('ws-b', 'p\u{e9}2', 'q\"2');
             insert into guard_supply_chain_bundle_cache values ('ws-a', 'p1', 'q1');",
        )
        .expect("bundles");
    let digest = call(&connection, "workspace_assessment_feed_digest", json!({})).expect("digest");
    // hashlib.sha256(b"guard.workspace-feed.v1\0" + json.dumps(rows, separators=(",", ":")))
    assert_eq!(
        digest,
        "668fc9a5529fe12a5406c391cc16ef6c455debb67bc86cf6b1c592cf8f2ce4af"
    );
}
