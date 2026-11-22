//! The workspace assessment read models against an in-memory copy of the
//! tables `store_workspace_assessment_schema.py` creates.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{dispatch, handles, PAGE_BYTES};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_op_kind::{method_kind, Kind};

const SCHEMA: &str = "
create table workspace_assessment_state (
    codebase_key text not null, worktree_key text not null, private_root text not null,
    dirty_generation integer not null default 0,
    last_completed_generation integer not null default 0,
    last_scan_at_ms integer, paused integer not null default 0,
    admitted_at_ms integer not null,
    primary key (codebase_key, worktree_key)
);
create table workspace_assessment_ended_admissions (
    codebase_key text not null, worktree_key text not null, ended_at_ms integer not null,
    primary key (codebase_key, worktree_key)
);
create table workspace_assessment_runs (
    run_id text not null primary key, codebase_key text not null, worktree_key text not null,
    snapshot_digest text, kind text not null, trigger_kind text not null, state text not null,
    dirty_generation integer not null, coverage_json text not null default '{}',
    findings_json text not null default '[]', error_code text,
    created_at_ms integer not null, started_at_ms integer, finished_at_ms integer
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

fn admit(connection: &Connection, codebase: &str, worktree: &str, admitted: i64, paused: i64) {
    connection
        .execute(
            "insert into workspace_assessment_state (codebase_key, worktree_key, private_root, \
             dirty_generation, last_completed_generation, paused, admitted_at_ms) \
             values (?1, ?2, ?3, 2, 1, ?4, ?5)",
            rusqlite::params![
                codebase,
                worktree,
                format!("/w/{worktree}"),
                paused,
                admitted
            ],
        )
        .expect("admit");
}

fn run(
    connection: &Connection,
    run_id: &str,
    worktree: &str,
    state: &str,
    created: i64,
    finished: Option<i64>,
) {
    connection
        .execute(
            "insert into workspace_assessment_runs (run_id, codebase_key, worktree_key, \
             snapshot_digest, kind, trigger_kind, state, dirty_generation, coverage_json, \
             findings_json, created_at_ms, finished_at_ms) \
             values (?1, 'c', ?2, 'd', 'deterministic', 'manual', ?3, 1, \
                     '{\"z\":1,\"a\":2}', '[{\"id\":1},{\"id\":2}]', ?4, ?5)",
            rusqlite::params![run_id, worktree, state, created, finished],
        )
        .expect("run");
}

fn ids(page: &Value, key: &str) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item[key].as_str().expect("key").to_owned())
        .collect()
}

#[test]
fn the_reads_are_routed_read_methods() {
    for method in [
        "list_workspace_assessment_worktrees",
        "list_workspace_assessment_runs",
        "latest_workspace_assessment_run",
    ] {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Read)));
    }
    assert!(!handles("latest_assessed_runs"));
}

#[test]
fn worktrees_come_back_in_admission_order_with_ended_and_paused() {
    let connection = store();
    admit(&connection, "c", "w2", 20, 0);
    admit(&connection, "c", "w1", 10, 1);
    admit(&connection, "c", "w3", 20, 0);
    connection
        .execute_batch("insert into workspace_assessment_ended_admissions values ('c', 'w1', 30)")
        .expect("ended");

    let page = call(
        &connection,
        "list_workspace_assessment_worktrees",
        json!({}),
    )
    .expect("page");
    assert_eq!(ids(&page, "worktree_key"), ["w1", "w2", "w3"]);
    assert_eq!(page["next"], Value::Null);
    let first = &page["items"][0];
    assert_eq!(first["root"], "/w/w1");
    assert_eq!(first["paused"], 1);
    assert_eq!(first["ended"], 1);
    assert_eq!(first["dirty_generation"], 2);
    assert_eq!(first["last_completed_generation"], 1);
    assert_eq!(page["items"][1]["ended"], 0);

    let active = call(
        &connection,
        "list_workspace_assessment_worktrees",
        json!({"include_paused": false}),
    )
    .expect("active");
    assert_eq!(ids(&active, "worktree_key"), ["w2", "w3"]);

    let after = call(
        &connection,
        "list_workspace_assessment_worktrees",
        json!({"after": [20, "w2", "c"]}),
    )
    .expect("after");
    assert_eq!(ids(&after, "worktree_key"), ["w3"]);
}

#[test]
fn a_large_worktree_list_is_read_in_pages() {
    let connection = store();
    let root = "r".repeat(4000);
    for index in 0..400 {
        connection
            .execute(
                "insert into workspace_assessment_state (codebase_key, worktree_key, \
                 private_root, admitted_at_ms) values ('c', ?1, ?2, ?3)",
                rusqlite::params![format!("w{index:04}"), root, index],
            )
            .expect("admit");
    }
    let mut seen = Vec::new();
    let mut args = json!({});
    loop {
        let page = call(&connection, "list_workspace_assessment_worktrees", args).expect("page");
        let encoded = serde_json::to_string(&page["items"]).expect("encode").len();
        assert!(encoded <= PAGE_BYTES + 8192);
        seen.extend(ids(&page, "worktree_key"));
        if page["next"].is_null() {
            break;
        }
        args = json!({"after": page["next"]});
    }
    let expected: Vec<String> = (0..400).map(|index| format!("w{index:04}")).collect();
    assert_eq!(seen, expected);
}

#[test]
fn recent_runs_are_newest_first_with_a_finding_count() {
    let connection = store();
    run(&connection, "r1", "w1", "completed", 10, Some(11));
    run(&connection, "r2", "w2", "queued", 20, None);
    run(&connection, "r3", "w1", "failed", 20, Some(21));

    let page = call(
        &connection,
        "list_workspace_assessment_runs",
        json!({"mode": "recent"}),
    )
    .expect("page");
    assert_eq!(ids(&page, "run_id"), ["r3", "r2", "r1"]);
    let newest = &page["items"][0];
    assert_eq!(newest["finding_count"], 2);
    assert_eq!(newest["coverage_json"], "{\"z\":1,\"a\":2}");
    assert!(newest.get("findings_json").is_none());

    let scoped = call(
        &connection,
        "list_workspace_assessment_runs",
        json!({"mode": "recent", "codebase_key": "c", "worktree_key": "w1", "limit": 1}),
    )
    .expect("scoped");
    assert_eq!(ids(&scoped, "run_id"), ["r3"]);

    let before = call(
        &connection,
        "list_workspace_assessment_runs",
        json!({"mode": "recent", "before": [20, "r2"]}),
    )
    .expect("before");
    assert_eq!(ids(&before, "run_id"), ["r1"]);
}

#[test]
fn latest_runs_keep_the_newest_run_of_every_worktree() {
    let connection = store();
    run(&connection, "r1", "w1", "completed", 10, Some(11));
    run(&connection, "r2", "w2", "queued", 15, None);
    run(&connection, "r3", "w1", "failed", 20, Some(21));

    let page = call(
        &connection,
        "list_workspace_assessment_runs",
        json!({"mode": "latest"}),
    )
    .expect("page");
    assert_eq!(ids(&page, "run_id"), ["r3", "r2"]);
}

#[test]
fn latest_runs_are_not_cut_at_the_history_limit() {
    let connection = store();
    for index in 0..250 {
        run(
            &connection,
            &format!("r{index:03}"),
            &format!("w{index:03}"),
            "queued",
            index,
            None,
        );
    }

    let page = call(
        &connection,
        "list_workspace_assessment_runs",
        json!({"mode": "latest"}),
    )
    .expect("page");
    assert_eq!(page["items"].as_array().map(Vec::len), Some(250));
    assert_eq!(page["next"], Value::Null);
}

#[test]
fn the_latest_assessed_run_skips_runs_without_results() {
    let connection = store();
    run(&connection, "r1", "w1", "completed", 10, Some(30));
    run(&connection, "r2", "w1", "partial", 12, Some(30));
    run(&connection, "r3", "w1", "failed", 20, Some(40));

    let latest = call(
        &connection,
        "latest_workspace_assessment_run",
        json!({"codebase_key": "c", "worktree_key": "w1"}),
    )
    .expect("latest");
    assert_eq!(latest["run_id"], "r2");
    assert_eq!(latest["findings_json"], "[{\"id\":1},{\"id\":2}]");

    let none = call(
        &connection,
        "latest_workspace_assessment_run",
        json!({"codebase_key": "c", "worktree_key": "w9"}),
    )
    .expect("none");
    assert_eq!(none, Value::Null);
}

#[test]
fn malformed_arguments_are_refused() {
    let connection = store();
    let cases = [
        (
            "list_workspace_assessment_worktrees",
            json!({"include_paused": 1}),
        ),
        (
            "list_workspace_assessment_worktrees",
            json!({"after": [1, "w"]}),
        ),
        (
            "list_workspace_assessment_worktrees",
            json!({"after": ["1", "w", "c"]}),
        ),
        ("list_workspace_assessment_runs", json!({"mode": "all"})),
        (
            "list_workspace_assessment_runs",
            json!({"mode": "recent", "limit": "5"}),
        ),
        (
            "list_workspace_assessment_runs",
            json!({"mode": "recent", "before": [1]}),
        ),
    ];
    for (method, args) in cases {
        assert!(
            matches!(call(&connection, method, args), Err(StoreError::Value(_))),
            "{method} accepted malformed arguments"
        );
    }
    assert!(matches!(
        call(&connection, "list_workspace_assessment_runs", json!({})),
        Err(StoreError::Invalid(_))
    ));
    let mut missing = Map::new();
    missing.insert("codebase_key".to_owned(), json!("c"));
    assert!(matches!(
        dispatch(
            &connection,
            "latest_workspace_assessment_run",
            &Args(&missing)
        ),
        Err(StoreError::Invalid(_))
    ));
}
