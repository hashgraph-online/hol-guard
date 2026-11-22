//! Worktree admissions against the in-memory queue tables.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::super::assessment_queue::tests::{admit as seed, key, keys, store, with};
use super::{dispatch, handles};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_op_kind::{method_kind, Kind};

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(map) = args else {
        panic!("args must be an object");
    };
    dispatch(connection, method, &Args(&map))
}

fn admit(
    connection: &Connection,
    worktree: &str,
    root: &str,
    automatic: bool,
    run_id: &str,
) -> Value {
    call(
        connection,
        "admit_workspace_assessment",
        json!({
            "codebase_key": key("c"), "worktree_key": key(worktree), "root": root, "now_ms": 5,
            "automatic": automatic, "stat_digest": key("s"), "feed_digest": null,
            "detector_set_digest": key("d"), "run_id": run_id,
        }),
    )
    .expect("admit")
}

fn count(connection: &Connection, sql: &str) -> i64 {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn roots(connection: &Connection, unavailable: &str) -> Value {
    call(
        connection,
        "workspace_assessment_watched_roots",
        json!({"unavailable_digest": unavailable}),
    )
    .expect("roots")
}

fn is_manual(connection: &Connection, worktree: &str, root: &str) -> Value {
    call(
        connection,
        "is_manual_workspace_assessment_admission",
        json!({"codebase_key": key("c"), "worktree_key": key(worktree), "root": root}),
    )
    .expect("manual")
}

#[test]
fn every_method_is_routed_with_its_kind() {
    for (method, write) in [
        ("admit_workspace_assessment", true),
        ("set_workspace_assessment_paused", true),
        ("record_workspace_assessment_observation", true),
        ("workspace_assessment_watched_roots", false),
        ("is_manual_workspace_assessment_admission", false),
        ("end_unregistered_workspace_assessment_admissions", true),
    ] {
        assert!(handles(method), "{method}");
        let kind = method_kind(method);
        if write {
            assert!(matches!(kind, Some(Kind::Write)), "{method}");
        } else {
            assert!(matches!(kind, Some(Kind::Read)), "{method}");
        }
    }
}

#[test]
fn a_manual_admission_records_its_observation_and_queues_its_first_run() {
    let connection = store();
    assert_eq!(admit(&connection, "a", "/w/a", false, "r1"), json!("r1"));
    let (stat, generation, trigger): (String, i64, String) = connection
        .query_row(
            "select s.observed_stat_digest, s.dirty_generation, r.trigger_kind \
             from workspace_assessment_state s join workspace_assessment_runs r using (worktree_key)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("admitted");
    assert_eq!(
        (stat, generation, trigger.as_str()),
        (key("s"), 1, "workspace_open")
    );
    assert_eq!(is_manual(&connection, "a", "/w/a"), json!(true));
    assert_eq!(is_manual(&connection, "a", "/w/b"), json!(false));
}

#[test]
fn an_automatic_admission_leaves_an_admitted_worktree_alone() {
    let connection = store();
    seed(&connection, "a", 1);
    assert_eq!(admit(&connection, "a", "/w/new", true, "r1"), Value::Null);
    assert_eq!(
        count(
            &connection,
            "select count(*) from workspace_assessment_runs"
        ),
        0
    );
    // A manual one takes it over and resumes it.
    assert_eq!(admit(&connection, "a", "/w/new", false, "r2"), json!("r2"));
    assert_eq!(
        count(&connection, "select paused from workspace_assessment_state"),
        0
    );
}

#[test]
fn an_automatic_admission_ends_the_one_its_root_used_to_name() {
    let connection = store();
    assert_eq!(admit(&connection, "a", "/w/x", true, "r1"), json!("r1"));
    assert_eq!(is_manual(&connection, "a", "/w/x"), json!(false));
    assert_eq!(admit(&connection, "b", "/w/x", true, "r2"), json!("r2"));
    let paused: i64 = connection
        .query_row(
            "select paused from workspace_assessment_state where worktree_key = ?1",
            [key("a")],
            |row| row.get(0),
        )
        .expect("paused");
    assert_eq!(paused, 1);
    assert_eq!(
        count(
            &connection,
            "select count(*) from workspace_assessment_ended_admissions"
        ),
        1
    );
    assert_eq!(
        roots(&connection, &key("u")),
        json!({"items": ["/w/x"], "next": null})
    );
    // A new registration revives an ended automatic admission.
    assert_eq!(admit(&connection, "a", "/w/y", true, "r3"), json!("r1"));
    assert_eq!(
        count(
            &connection,
            "select count(*) from workspace_assessment_ended_admissions"
        ),
        0
    );
}

#[test]
fn unavailable_and_ended_roots_are_not_watched() {
    let connection = store();
    admit(&connection, "a", "/w/a", false, "r1");
    admit(&connection, "b", "/w/b", false, "r2");
    assert_eq!(
        roots(&connection, &key("u")),
        json!({"items": ["/w/a", "/w/b"], "next": null})
    );
    assert_eq!(
        roots(&connection, &key("s")),
        json!({"items": [], "next": null})
    );
    let after = call(
        &connection,
        "workspace_assessment_watched_roots",
        json!({"unavailable_digest": key("u"), "after": [key("c"), key("a")]}),
    )
    .expect("after");
    assert_eq!(after, json!({"items": ["/w/b"], "next": null}));
    let bad = call(
        &connection,
        "workspace_assessment_watched_roots",
        json!({"unavailable_digest": key("u"), "after": "x"}),
    );
    assert!(matches!(bad, Err(StoreError::Value(_))));
}

#[test]
fn a_long_root_list_pages_under_the_budget() {
    let connection = store();
    let root = "r".repeat(4000);
    for index in 0..300 {
        let worktree = format!("w{index:03}");
        connection
            .execute(
                "insert into workspace_assessment_state \
                 (codebase_key, worktree_key, private_root, admitted_at_ms) values (?1, ?2, ?3, 0)",
                rusqlite::params![key("c"), key(&worktree), root],
            )
            .expect("seed");
    }
    let mut seen = 0;
    let mut after = Value::Null;
    loop {
        let page = call(
            &connection,
            "workspace_assessment_watched_roots",
            json!({"unavailable_digest": key("u"), "after": after}),
        )
        .expect("page");
        let items = page["items"].as_array().expect("items").len();
        assert!(items > 0);
        seen += items;
        after = page["next"].clone();
        if after.is_null() {
            break;
        }
    }
    assert_eq!(seen, 300);
}

#[test]
fn unregistered_install_admissions_end_and_keep_their_records() {
    let connection = store();
    admit(&connection, "a", "/w/a", true, "r1");
    admit(&connection, "b", "/w/b", true, "r2");
    admit(&connection, "m", "/w/m", false, "r3");
    let ended = call(
        &connection,
        "end_unregistered_workspace_assessment_admissions",
        json!({"registered_roots": ["/w/b"], "now_ms": 9}),
    )
    .expect("end");
    assert_eq!(ended, json!(1));
    assert_eq!(
        count(
            &connection,
            "select count(*) from workspace_assessment_install_admissions"
        ),
        1
    );
    assert_eq!(
        count(
            &connection,
            "select count(*) from workspace_assessment_runs"
        ),
        3
    );
    assert_eq!(
        count(
            &connection,
            "select sum(paused) from workspace_assessment_state"
        ),
        1
    );
    let missing = call(
        &connection,
        "end_unregistered_workspace_assessment_admissions",
        json!({"now_ms": 9}),
    );
    assert!(matches!(missing, Err(StoreError::Value(_))));
}

#[test]
fn pausing_and_resuming_clears_an_ended_admission() {
    let connection = store();
    seed(&connection, "a", 0);
    connection
        .execute(
            "insert into workspace_assessment_ended_admissions values (?1, ?2, 1)",
            rusqlite::params![key("c"), key("a")],
        )
        .expect("ended");
    let pause = |paused: Value| {
        call(
            &connection,
            "set_workspace_assessment_paused",
            with(keys("a"), json!({"paused": paused})),
        )
    };
    assert_eq!(pause(json!(true)).expect("pause"), json!(true));
    let ended = |connection: &Connection| -> i64 {
        connection
            .query_row(
                "select count(*) from workspace_assessment_ended_admissions",
                [],
                |row| row.get(0),
            )
            .expect("count")
    };
    assert_eq!(ended(&connection), 1);
    assert_eq!(pause(json!(false)).expect("resume"), json!(true));
    assert_eq!(ended(&connection), 0);
    assert!(matches!(pause(json!(1)), Err(StoreError::Value(_))));
    let missing = call(
        &connection,
        "set_workspace_assessment_paused",
        with(keys("zz"), json!({"paused": false})),
    );
    assert_eq!(missing.expect("missing"), json!(false));
}

#[test]
fn an_observation_reports_only_changes_from_an_earlier_one() {
    let connection = store();
    seed(&connection, "a", 0);
    let observe = |stat: Value, feed: Value| {
        call(
            &connection,
            "record_workspace_assessment_observation",
            with(keys("a"), json!({"stat_digest": stat, "feed_digest": feed})),
        )
        .expect("observe")
    };
    assert_eq!(observe(json!(key("s1")), json!(key("f1"))), json!([]));
    assert_eq!(observe(json!(key("s1")), Value::Null), json!([]));
    assert_eq!(
        observe(json!(key("s2")), json!(key("f2"))),
        json!(["file_change", "feed_change"])
    );
    assert_eq!(
        observe(Value::Null, json!(key("f3"))),
        json!(["feed_change"])
    );
    seed(&connection, "p", 1);
    let paused = call(
        &connection,
        "record_workspace_assessment_observation",
        with(keys("p"), json!({"stat_digest": key("s")})),
    );
    assert_eq!(paused.expect("paused"), json!([]));
}
