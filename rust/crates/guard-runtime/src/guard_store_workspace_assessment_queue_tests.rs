//! The workspace assessment queue against an in-memory copy of the tables
//! `store_workspace_assessment_schema.py` creates.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{dispatch, handles, DEBOUNCE_MS, LEASE_MS, MAX_DEBOUNCE_WAIT_MS, MIN_INTERVAL_MS};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_op_kind::{method_kind, Kind};

pub(crate) const SCHEMA: &str = "
create table workspace_assessment_state (
    codebase_key text not null check (length(codebase_key) = 64),
    worktree_key text not null check (length(worktree_key) = 64),
    private_root text not null,
    observed_stat_digest text, observed_feed_digest text,
    dirty_generation integer not null default 0 check (dirty_generation >= 0),
    last_completed_generation integer not null default 0,
    last_scan_at_ms integer,
    paused integer not null default 0 check (paused in (0, 1)),
    admitted_at_ms integer not null,
    primary key (codebase_key, worktree_key),
    check (last_completed_generation >= 0 and last_completed_generation <= dirty_generation)
);
create table workspace_assessment_install_admissions (
    codebase_key text not null, worktree_key text not null,
    primary key (codebase_key, worktree_key)
);
create table workspace_assessment_ended_admissions (
    codebase_key text not null, worktree_key text not null, ended_at_ms integer not null,
    primary key (codebase_key, worktree_key)
);
create table workspace_assessment_runs (
    run_id text not null primary key check (length(run_id) <= 64),
    codebase_key text not null, worktree_key text not null,
    snapshot_digest text, input_manifest_digest text,
    detector_set_digest text not null check (length(detector_set_digest) = 64),
    feed_context_digest text,
    kind text not null check (kind in ('deterministic', 'verification')),
    trigger_kind text not null check (trigger_kind in
        ('workspace_open', 'file_change', 'feed_change', 'manual', 'fix_verification')),
    state text not null check (state in
        ('queued', 'running', 'completed', 'partial', 'failed', 'canceled', 'superseded')),
    dirty_generation integer not null,
    lease_generation integer not null default 0,
    lease_owner text, lease_until_ms integer,
    coverage_json text not null default '{}', findings_json text not null default '[]',
    error_code text,
    created_at_ms integer not null,
    triggered_at_ms integer not null check (triggered_at_ms >= created_at_ms),
    started_at_ms integer, finished_at_ms integer,
    check (state != 'running' or (lease_owner is not null and lease_until_ms is not null))
);
create unique index workspace_assessment_one_active
on workspace_assessment_runs (codebase_key, worktree_key) where state = 'running';
create unique index workspace_assessment_one_queued
on workspace_assessment_runs (codebase_key, worktree_key) where state = 'queued';
";

pub(crate) fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection.execute_batch(SCHEMA).expect("schema");
    connection
}

pub(crate) fn key(label: &str) -> String {
    format!("{label:0>64}")
}

pub(crate) fn admit(connection: &Connection, worktree: &str, paused: i64) {
    connection
        .execute(
            "insert into workspace_assessment_state \
             (codebase_key, worktree_key, private_root, paused, admitted_at_ms) \
             values (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![key("c"), key(worktree), format!("/w/{worktree}"), paused],
        )
        .expect("admit");
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(map) = args else {
        panic!("args must be an object");
    };
    dispatch(connection, method, &Args(&map))
}

pub(crate) fn keys(worktree: &str) -> Value {
    json!({"codebase_key": key("c"), "worktree_key": key(worktree)})
}

pub(crate) fn with(base: Value, extra: Value) -> Value {
    let (Value::Object(mut base), Value::Object(extra)) = (base, extra) else {
        panic!("objects");
    };
    base.extend(extra);
    Value::Object(base)
}

fn enqueue(
    connection: &Connection,
    worktree: &str,
    trigger: &str,
    run_id: &str,
    now: i64,
) -> Value {
    call(
        connection,
        "enqueue_workspace_assessment",
        with(
            keys(worktree),
            json!({"trigger_kind": trigger, "detector_set_digest": key("d"), "kind": "deterministic",
                   "now_ms": now, "run_id": run_id}),
        ),
    )
    .expect("enqueue")
}

fn claim(connection: &Connection, now: i64) -> Value {
    call(
        connection,
        "claim_workspace_assessment",
        json!({"owner": "w1", "now_ms": now}),
    )
    .expect("claim")
}

fn column(connection: &Connection, run_id: &str, name: &str) -> Value {
    let sql = format!("select {name} from workspace_assessment_runs where run_id = ?1");
    connection
        .query_row(&sql, [run_id], |row| {
            let value: rusqlite::types::Value = row.get(0)?;
            Ok(match value {
                rusqlite::types::Value::Integer(n) => json!(n),
                rusqlite::types::Value::Text(t) => json!(t),
                _ => Value::Null,
            })
        })
        .expect("column")
}

fn finish(connection: &Connection, claimed: &Value, state: &str, now: i64) -> Value {
    call(
        connection,
        "finish_workspace_assessment",
        json!({
            "codebase_key": claimed["codebase_key"], "worktree_key": claimed["worktree_key"],
            "run_id": claimed["run_id"], "lease_generation": claimed["lease_generation"],
            "dirty_generation": claimed["dirty_generation"], "trigger_kind": claimed["trigger_kind"],
            "kind": claimed["kind"], "detector_set_digest": claimed["detector_set_digest"],
            "state": state, "snapshot_digest": key("s"), "input_manifest_digest": null,
            "feed_context_digest": key("f"), "coverage_json": "{}", "findings_json": "[]",
            "error_code": null, "now_ms": now,
        }),
    )
    .expect("finish")
}

#[test]
fn every_method_is_routed_and_writes() {
    for method in [
        "enqueue_workspace_assessment",
        "claim_workspace_assessment",
        "finish_workspace_assessment",
        "renew_workspace_assessment_lease",
        "cancel_workspace_assessment",
    ] {
        assert!(handles(method), "{method}");
        assert!(matches!(method_kind(method), Some(Kind::Write)), "{method}");
    }
    assert!(!handles("list_workspace_assessment_worktrees"));
}

#[test]
fn a_trigger_queues_one_run_and_coalesces_later_ones() {
    let connection = store();
    admit(&connection, "a", 0);
    assert_eq!(
        enqueue(&connection, "a", "file_change", "r1", 10),
        json!("r1")
    );
    assert_eq!(enqueue(&connection, "a", "manual", "r2", 20), json!("r1"));
    assert_eq!(column(&connection, "r1", "trigger_kind"), json!("manual"));
    assert_eq!(column(&connection, "r1", "dirty_generation"), json!(2));
    assert_eq!(column(&connection, "r1", "triggered_at_ms"), json!(20));
    // An automatic trigger never downgrades a user request.
    enqueue(&connection, "a", "file_change", "r3", 30);
    assert_eq!(column(&connection, "r1", "trigger_kind"), json!("manual"));
}

#[test]
fn a_paused_or_unknown_worktree_queues_nothing() {
    let connection = store();
    admit(&connection, "p", 1);
    assert_eq!(enqueue(&connection, "p", "manual", "r1", 1), Value::Null);
    assert_eq!(enqueue(&connection, "x", "manual", "r1", 1), Value::Null);
}

#[test]
fn an_unknown_trigger_or_kind_is_refused() {
    let connection = store();
    admit(&connection, "a", 0);
    let bad_trigger = call(
        &connection,
        "enqueue_workspace_assessment",
        with(
            keys("a"),
            json!({"trigger_kind": "cron", "detector_set_digest": key("d"), "kind": "deterministic",
                   "now_ms": 1, "run_id": "r1"}),
        ),
    );
    assert!(matches!(bad_trigger, Err(StoreError::Value(_))));
    let bad_kind = call(
        &connection,
        "enqueue_workspace_assessment",
        with(
            keys("a"),
            json!({"trigger_kind": "manual", "detector_set_digest": key("d"), "kind": "deep",
                   "now_ms": 1, "run_id": "r1"}),
        ),
    );
    assert!(matches!(bad_kind, Err(StoreError::Value(_))));
}

#[test]
fn an_automatic_run_waits_for_the_debounce_and_interval() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "file_change", "r1", 1_000);
    assert_eq!(claim(&connection, 1_000 + DEBOUNCE_MS - 1), Value::Null);
    let claimed = claim(&connection, 1_000 + DEBOUNCE_MS);
    assert_eq!(claimed["run_id"], json!("r1"));
    assert_eq!(claimed["private_root"], json!("/w/a"));
    assert_eq!(claimed["lease_generation"], json!(1));
    assert_eq!(column(&connection, "r1", "state"), json!("running"));
    assert_eq!(
        column(&connection, "r1", "lease_until_ms"),
        json!(1_000 + DEBOUNCE_MS + LEASE_MS)
    );
    let now = 1_000 + DEBOUNCE_MS + 10;
    assert_eq!(finish(&connection, &claimed, "completed", now), json!(true));
    enqueue(&connection, "a", "file_change", "r2", now);
    // The interval since the last scan holds the next automatic run back.
    assert_eq!(claim(&connection, now + MIN_INTERVAL_MS - 1), Value::Null);
    assert_eq!(
        claim(&connection, now + MIN_INTERVAL_MS)["run_id"],
        json!("r2")
    );
}

#[test]
fn edits_that_never_pause_are_still_assessed() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "file_change", "r1", 0);
    for at in (1_000..MAX_DEBOUNCE_WAIT_MS).step_by(1_000) {
        enqueue(&connection, "a", "file_change", "r9", at);
        assert_eq!(claim(&connection, at), Value::Null);
    }
    assert_eq!(
        claim(&connection, MAX_DEBOUNCE_WAIT_MS)["run_id"],
        json!("r1")
    );
}

#[test]
fn user_only_leaves_automatic_runs_queued() {
    let connection = store();
    admit(&connection, "a", 0);
    admit(&connection, "b", 0);
    enqueue(&connection, "a", "file_change", "r1", 0);
    enqueue(&connection, "b", "manual", "r2", 1);
    let args = json!({"owner": "w", "now_ms": 999_999, "user_only": true, "detector_set_digest": key("e")});
    let claimed = call(&connection, "claim_workspace_assessment", args.clone()).expect("claim");
    assert_eq!(claimed["run_id"], json!("r2"));
    // The caller's detector set relabels the run it claims.
    assert_eq!(claimed["detector_set_digest"], json!(key("e")));
    assert_eq!(
        column(&connection, "r2", "detector_set_digest"),
        json!(key("e"))
    );
    assert_eq!(
        call(&connection, "claim_workspace_assessment", args).expect("claim"),
        Value::Null
    );
}

#[test]
fn the_device_runs_at_most_two_assessments() {
    let connection = store();
    for (worktree, run) in [("a", "r1"), ("b", "r2"), ("e", "r3")] {
        admit(&connection, worktree, 0);
        enqueue(&connection, worktree, "manual", run, 0);
    }
    assert_eq!(claim(&connection, 1)["run_id"], json!("r1"));
    assert_eq!(claim(&connection, 1)["run_id"], json!("r2"));
    assert_eq!(claim(&connection, 1), Value::Null);
}

#[test]
fn an_expired_lease_is_retried_once() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "manual", "r1", 0);
    claim(&connection, 0);
    let first_expiry = LEASE_MS + 1;
    let retry = claim(&connection, first_expiry);
    assert_eq!(
        column(&connection, "r1", "error_code"),
        json!("lease_expired")
    );
    assert_eq!(column(&connection, "r1", "lease_generation"), json!(2));
    let retry_id = retry["run_id"].as_str().expect("retry id").to_owned();
    assert_eq!(retry_id.len(), 32);
    assert!(retry_id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(retry["trigger_kind"], json!("manual"));
    // The retry also expires: it fails as timed out and nothing is queued.
    assert_eq!(claim(&connection, first_expiry + LEASE_MS + 1), Value::Null);
    assert_eq!(
        column(&connection, &retry_id, "error_code"),
        json!("assessment_timed_out")
    );
}

#[test]
fn only_the_current_lease_can_finish_renew_or_be_canceled() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "manual", "r1", 0);
    let claimed = claim(&connection, 0);
    let renew = |generation: i64, now: i64| {
        call(
            &connection,
            "renew_workspace_assessment_lease",
            json!({"run_id": "r1", "lease_generation": generation, "now_ms": now}),
        )
        .expect("renew")
    };
    assert_eq!(renew(9, 5), json!(false));
    assert_eq!(renew(1, 5), json!(true));
    assert_eq!(
        column(&connection, "r1", "lease_until_ms"),
        json!(5 + LEASE_MS)
    );
    let cancel = || {
        call(
            &connection,
            "cancel_workspace_assessment",
            json!({"run_id": "r1", "now_ms": 7}),
        )
        .expect("cancel")
    };
    assert_eq!(cancel(), json!(true));
    assert_eq!(cancel(), json!(false));
    assert_eq!(renew(1, 8), json!(false));
    assert_eq!(finish(&connection, &claimed, "completed", 9), json!(false));
    assert_eq!(column(&connection, "r1", "state"), json!("canceled"));
}

#[test]
fn a_completed_run_advances_the_worktree() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "manual", "r1", 0);
    let claimed = claim(&connection, 0);
    enqueue(&connection, "a", "file_change", "r2", 1);
    assert_eq!(finish(&connection, &claimed, "partial", 3), json!(true));
    let (completed, dirty, scanned, feed): (i64, i64, i64, String) = connection
        .query_row(
            "select last_completed_generation, dirty_generation, last_scan_at_ms, \
             observed_feed_digest from workspace_assessment_state",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("state");
    assert_eq!((completed, dirty, scanned), (1, 2, 3));
    assert_eq!(feed, key("f"));
    assert_eq!(column(&connection, "r1", "lease_owner"), Value::Null);
}

#[test]
fn a_superseded_run_queues_one_successor() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "fix_verification", "r1", 0);
    let claimed = claim(&connection, 0);
    assert_eq!(finish(&connection, &claimed, "superseded", 4), json!(true));
    let (successor, trigger): (String, String) = connection
        .query_row(
            "select run_id, trigger_kind from workspace_assessment_runs where state = 'queued'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("successor");
    assert_eq!(successor.len(), 32);
    assert_eq!(trigger, "fix_verification");
    let completed: i64 = connection
        .query_row(
            "select last_completed_generation from workspace_assessment_state",
            [],
            |row| row.get(0),
        )
        .expect("state");
    assert_eq!(completed, 0);
}

#[test]
fn an_invalid_outcome_state_is_refused() {
    let connection = store();
    admit(&connection, "a", 0);
    enqueue(&connection, "a", "manual", "r1", 0);
    let claimed = claim(&connection, 0);
    let refused = call(
        &connection,
        "finish_workspace_assessment",
        json!({"codebase_key": claimed["codebase_key"], "worktree_key": claimed["worktree_key"],
               "state": "canceled", "now_ms": 1}),
    );
    assert!(matches!(refused, Err(StoreError::Value(_))));
}
