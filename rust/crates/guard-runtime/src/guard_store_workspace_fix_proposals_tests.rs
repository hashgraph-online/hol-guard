//! The workspace fix proposal rows against an in-memory copy of the tables
//! `store_workspace_assessment_schema.py` creates.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{dispatch, handles, PAGE_BYTES};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_op_kind::{method_kind, Kind};

const SCHEMA: &str = "
create table workspace_assessment_state (
    codebase_key text not null, worktree_key text not null, private_root text not null,
    paused integer not null default 0,
    primary key (codebase_key, worktree_key)
);
create table workspace_assessment_runs (
    run_id text not null primary key, codebase_key text not null, worktree_key text not null,
    state text not null, finished_at_ms integer
);
create table workspace_fix_proposals (
    proposal_id text not null primary key, codebase_key text not null, worktree_key text not null,
    finding_id text not null, ecosystem text not null, package_name text not null,
    fix_version text not null, advisory_ids_json text not null, rule_ids_json text not null,
    source_run_id text not null, snapshot_digest text not null, manifest_path text not null,
    base_sha256 text not null, new_sha256 text not null, edits_json text not null,
    diff_text text not null, state text not null, created_at_ms integer not null,
    updated_at_ms integer not null check (updated_at_ms >= created_at_ms),
    applied_at_ms integer, verified_at_ms integer, verification_run_id text
);
";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection.execute_batch(SCHEMA).expect("schema");
    connection
        .execute(
            "insert into workspace_assessment_state values ('c', 'w', '/w/root', 1)",
            [],
        )
        .expect("admit");
    connection
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(map) = args else {
        panic!("args must be an object");
    };
    dispatch(connection, method, &Args(&map))
}

fn proposal(connection: &Connection, id: &str, state: &str, created: i64, diff: &str) {
    connection
        .execute(
            "insert into workspace_fix_proposals values (?1, 'c', 'w', 'f', 'npm', 'left-pad', \
             '1.3.0', '[\"GHSA-1\"]', '[]', 'r0', 'd0', 'package.json', 'b', 'n', \
             '[{\"section\":\"dependencies\",\"start\":1,\"end\":2,\"from_spec\":\"1.0\",\"to_spec\":\"1.3.0\"}]', \
             ?2, ?3, ?4, ?4, case when ?3 = 'prepared' then null else ?4 end, null, null)",
            rusqlite::params![id, diff, state, created],
        )
        .expect("proposal");
}

fn finished_run(connection: &Connection, run_id: &str, finished: i64) {
    connection
        .execute(
            "insert into workspace_assessment_runs values (?1, 'c', 'w', 'completed', ?2)",
            rusqlite::params![run_id, finished],
        )
        .expect("run");
}

fn state_of(connection: &Connection, id: &str) -> (String, Option<String>) {
    connection
        .query_row(
            "select state, verification_run_id from workspace_fix_proposals where proposal_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("state")
}

#[test]
fn every_method_is_routed_with_its_transaction_kind() {
    for (method, kind) in [
        ("workspace_assessment_worktree_root", Kind::Read),
        ("list_workspace_fix_proposals", Kind::Read),
        ("get_workspace_fix_proposal", Kind::Read),
        ("list_workspace_fix_proposals_to_verify", Kind::Read),
        ("settle_workspace_fix_proposals", Kind::Write),
        ("store_prepared_workspace_fix_proposals", Kind::Write),
        ("set_workspace_fix_proposal_state", Kind::Write),
    ] {
        assert!(handles(method), "{method}");
        assert!(method_kind(method) == Some(kind), "{method}");
    }
    assert!(!handles("list_workspace_assessment_runs"));
}

#[test]
fn the_worktree_root_is_read_or_null() {
    let connection = store();
    let root = call(
        &connection,
        "workspace_assessment_worktree_root",
        json!({"codebase_key": "c", "worktree_key": "w"}),
    )
    .expect("root");
    assert_eq!(root, json!({"root": "/w/root", "paused": 1}));
    let missing = call(
        &connection,
        "workspace_assessment_worktree_root",
        json!({"codebase_key": "c", "worktree_key": "gone"}),
    )
    .expect("missing");
    assert_eq!(missing, Value::Null);
}

#[test]
fn listing_is_newest_first_and_hides_a_settled_diff() {
    let connection = store();
    proposal(&connection, "a", "prepared", 1, "diff-a");
    proposal(&connection, "b", "applied", 2, "diff-b");
    proposal(&connection, "c", "prepared", 2, "diff-c");
    let page = call(
        &connection,
        "list_workspace_fix_proposals",
        json!({"codebase_key": "c", "worktree_key": "w", "limit": 10}),
    )
    .expect("page");
    let items = page["items"].as_array().expect("items");
    let ids: Vec<&str> = items
        .iter()
        .map(|item| item["proposal_id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, ["c", "b", "a"]);
    assert_eq!(items[0]["diff_text"], "diff-c");
    assert_eq!(items[1]["diff_text"], Value::Null);
    assert_eq!(page["next"], Value::Null);
    assert_eq!(items[0].as_object().expect("row").len(), 22);
    let older = call(
        &connection,
        "list_workspace_fix_proposals",
        json!({"codebase_key": "c", "worktree_key": "w", "before": [2, "b"]}),
    )
    .expect("older");
    assert_eq!(older["items"][0]["proposal_id"], "a");
    let one = call(
        &connection,
        "list_workspace_fix_proposals",
        json!({"codebase_key": "c", "worktree_key": "w", "limit": 0}),
    )
    .expect("clamped");
    assert_eq!(one["items"].as_array().expect("items").len(), 1);
}

#[test]
fn a_large_listing_pages_under_the_budget() {
    let connection = store();
    let diff = "x".repeat(60_000);
    for index in 0..40 {
        proposal(
            &connection,
            &format!("p{index:02}"),
            "prepared",
            index,
            &diff,
        );
    }
    let args = json!({"codebase_key": "c", "worktree_key": "w", "limit": 100});
    let first = call(&connection, "list_workspace_fix_proposals", args).expect("first");
    let items = first["items"].as_array().expect("items");
    assert!(items.len() < 40);
    assert!(serde_json::to_string(&first).expect("encoded").len() < PAGE_BYTES + 70_000);
    let last = items.last().expect("last");
    assert_eq!(
        first["next"],
        json!([last["created_at_ms"], last["proposal_id"]])
    );
    // Each later page is held to the same budget, so keep paging to the end.
    let mut total = items.len();
    let mut next = first["next"].clone();
    while !next.is_null() {
        let page = call(
            &connection,
            "list_workspace_fix_proposals",
            json!({"codebase_key": "c", "worktree_key": "w", "limit": 100, "before": next}),
        )
        .expect("page");
        let page_items = page["items"].as_array().expect("items");
        assert!(!page_items.is_empty());
        total += page_items.len();
        next = page["next"].clone();
    }
    assert_eq!(total, 40);
}

#[test]
fn malformed_listing_arguments_are_refused() {
    let connection = store();
    for args in [
        json!({"codebase_key": "c", "worktree_key": "w", "limit": "3"}),
        json!({"codebase_key": "c", "worktree_key": "w", "before": [1]}),
        json!({"codebase_key": "c", "worktree_key": "w", "before": ["1", "a"]}),
        json!({"codebase_key": "c", "worktree_key": "w", "before": [1, 2]}),
    ] {
        let error = call(&connection, "list_workspace_fix_proposals", args).expect_err("refused");
        assert!(matches!(error, StoreError::Value(_)));
    }
    let error = call(
        &connection,
        "list_workspace_fix_proposals_to_verify",
        json!({"codebase_key": "c", "worktree_key": "w", "after": 3}),
    )
    .expect_err("refused");
    assert!(matches!(error, StoreError::Value(_)));
}

#[test]
fn get_reads_one_proposal_or_null() {
    let connection = store();
    proposal(&connection, "a", "stale", 1, "diff-a");
    let row = call(
        &connection,
        "get_workspace_fix_proposal",
        json!({"proposal_id": "a"}),
    )
    .expect("row");
    assert_eq!(row["state"], "stale");
    assert_eq!(row["diff_text"], Value::Null);
    assert_eq!(row["advisory_ids_json"], "[\"GHSA-1\"]");
    let missing = call(
        &connection,
        "get_workspace_fix_proposal",
        json!({"proposal_id": "z"}),
    )
    .expect("missing");
    assert_eq!(missing, Value::Null);
}

#[test]
fn only_applied_or_still_present_proposals_await_verification() {
    let connection = store();
    proposal(&connection, "a", "applied", 1, "");
    proposal(&connection, "b", "prepared", 1, "");
    proposal(&connection, "c", "still_present", 1, "");
    proposal(&connection, "d", "verified_fixed", 1, "");
    let page = call(
        &connection,
        "list_workspace_fix_proposals_to_verify",
        json!({"codebase_key": "c", "worktree_key": "w"}),
    )
    .expect("page");
    let ids: Vec<&str> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["proposal_id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, ["a", "c"]);
    assert_eq!(page["items"][0]["advisory_ids"], "[\"GHSA-1\"]");
    assert_eq!(page["items"][0].as_object().expect("row").len(), 10);
    let after = call(
        &connection,
        "list_workspace_fix_proposals_to_verify",
        json!({"codebase_key": "c", "worktree_key": "w", "after": "a"}),
    )
    .expect("after");
    assert_eq!(after["items"][0]["proposal_id"], "c");
}

#[test]
fn a_verdict_settles_only_while_its_run_is_newest_and_its_row_is_unchanged() {
    let connection = store();
    proposal(&connection, "a", "applied", 1, "");
    proposal(&connection, "b", "applied", 1, "");
    finished_run(&connection, "r1", 10);
    let settle = |run: &str| {
        call(
            &connection,
            "settle_workspace_fix_proposals",
            json!({
                "codebase_key": "c", "worktree_key": "w", "run_id": run, "now_ms": 20,
                "updates": [
                    {"proposal_id": "a", "state": "verified_fixed", "prior_state": "applied",
                     "prior_verification_run_id": null},
                    {"proposal_id": "b", "state": "still_present", "prior_state": "still_present",
                     "prior_verification_run_id": null},
                ],
            }),
        )
    };
    assert_eq!(settle("r0").expect("stale run"), Value::Bool(false));
    assert_eq!(state_of(&connection, "a").0, "applied");
    assert_eq!(settle("r1").expect("newest"), Value::Bool(true));
    assert_eq!(
        state_of(&connection, "a"),
        ("verified_fixed".to_owned(), Some("r1".to_owned()))
    );
    assert_eq!(state_of(&connection, "b"), ("applied".to_owned(), None));
}

#[test]
fn a_verdict_outside_the_two_outcomes_is_refused() {
    let connection = store();
    finished_run(&connection, "r1", 10);
    let error = call(
        &connection,
        "settle_workspace_fix_proposals",
        json!({
            "codebase_key": "c", "worktree_key": "w", "run_id": "r1", "now_ms": 20,
            "updates": [{"proposal_id": "a", "state": "prepared", "prior_state": "applied"}],
        }),
    )
    .expect_err("refused");
    assert!(matches!(error, StoreError::Value(_)));
}

fn prepare_args(items: Value) -> Value {
    json!({
        "codebase_key": "c", "worktree_key": "w", "finding_id": "f", "source_run_id": "r9",
        "snapshot_digest": "d0", "now_ms": 50, "ecosystem": "npm", "package_name": "left-pad",
        "fix_version": "1.3.0", "advisory_ids_json": "[\"GHSA-1\"]", "rule_ids_json": "[]",
        "items": items,
    })
}

#[test]
fn preparing_keeps_a_matching_proposal_and_stales_the_rest() {
    let connection = store();
    proposal(&connection, "same", "prepared", 1, "old");
    proposal(&connection, "other", "prepared", 2, "old");
    connection
        .execute(
            "update workspace_fix_proposals set base_sha256 = 'x' where proposal_id = 'other'",
            [],
        )
        .expect("diverge");
    let ids = call(
        &connection,
        "store_prepared_workspace_fix_proposals",
        prepare_args(json!([
            {"proposal_id": "fresh1", "manifest_path": "package.json", "base_sha256": "b",
             "new_sha256": "n", "edits_base64": "W10=", "diff_base64": "ZA=="},
            {"proposal_id": "fresh2", "manifest_path": "app/package.json", "base_sha256": "b",
             "new_sha256": "n", "edits_base64": "W10=", "diff_base64": "ZDI="},
        ])),
    )
    .expect("stored");
    assert_eq!(ids, json!(["same", "fresh2"]));
    assert_eq!(state_of(&connection, "other").0, "stale");
    assert_eq!(state_of(&connection, "same").0, "prepared");
    let row = call(
        &connection,
        "get_workspace_fix_proposal",
        json!({"proposal_id": "fresh2"}),
    )
    .expect("row");
    assert_eq!(row["diff_text"], "d2");
    assert_eq!(row["source_run_id"], "r9");
    assert_eq!(row["created_at_ms"], 50);
}

#[test]
fn proposal_text_arrives_as_base64_and_must_decode_to_utf8() {
    let connection = store();
    // "\u{7f}\u{7f}" would take twelve bytes as canonical JSON escapes.
    let ids = call(
        &connection,
        "store_prepared_workspace_fix_proposals",
        prepare_args(json!([{"proposal_id": "p", "manifest_path": "package.json",
            "base_sha256": "b", "new_sha256": "n", "edits_base64": "W10=",
            "diff_base64": "f38="}])),
    )
    .expect("stored");
    assert_eq!(ids, json!(["p"]));
    let row = call(
        &connection,
        "get_workspace_fix_proposal",
        json!({"proposal_id": "p"}),
    )
    .expect("row");
    assert_eq!(row["diff_text"], "\u{7f}\u{7f}");
    for diff in ["not base64!", "/w=="] {
        let error = call(
            &connection,
            "store_prepared_workspace_fix_proposals",
            prepare_args(
                json!([{"proposal_id": "q", "manifest_path": "app/package.json",
                "base_sha256": "b", "new_sha256": "n", "edits_base64": "W10=",
                "diff_base64": diff}]),
            ),
        )
        .expect_err("refused");
        assert!(matches!(error, StoreError::Value(_)));
    }
}

#[test]
fn only_a_prepared_proposal_changes_state() {
    let connection = store();
    proposal(&connection, "a", "prepared", 1, "");
    proposal(&connection, "b", "stale", 1, "");
    for id in ["a", "b"] {
        call(
            &connection,
            "set_workspace_fix_proposal_state",
            json!({"proposal_id": id, "state": "applied", "now_ms": 9, "applied": true}),
        )
        .expect("set");
    }
    let applied: (String, Option<i64>) = connection
        .query_row(
            "select state, applied_at_ms from workspace_fix_proposals where proposal_id = 'a'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("a");
    assert_eq!(applied, ("applied".to_owned(), Some(9)));
    assert_eq!(state_of(&connection, "b").0, "stale");
}
