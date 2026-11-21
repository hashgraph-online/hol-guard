//! Pins the writer ops the resident applies itself.

use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::params;
use serde_json::{json, Value};

use super::super::seals_tests::quarantined;
use super::super::tests::{catalog, local, read_request, run, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";
const SOON: &str = "2026-10-21T00:04:59.999999+00:00";

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn writer(home: &Home, op: &str, anchor_json: &str) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json.to_owned()),
        now: Some(NOW.to_owned()),
        ..home.request(op, &catalog('a'))
    }
}

#[test]
fn restore_writes_the_snapshot_its_baseline_and_the_event_once() {
    let home = Home::new();
    let head = quarantined(&home);
    let reply = run(&writer(&home, "restore", &head));
    assert_eq!(
        reply["restored"],
        json!({"revision": 2, "control_count": 1})
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition \
             where revision = 2 and phase = 'committed' and committed_at = '2026-10-21T00:05:00+00:00'"
        ),
        1
    );
    let (payload, occurred_at): (String, String) = home
        .db
        .query_row(
            "select payload_json, occurred_at from guard_events \
             where event_name = 'extension_control_authority_restored'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        payload,
        r#"{"control_count":1,"revision":2,"source":"last-good-export"}"#
    );
    assert_eq!(occurred_at, NOW);
    // The restored head reads back protected with its controls.
    let view = run(&read_request(&home, &catalog('a'), Some(head.clone())));
    assert_eq!(view["view"]["health"], json!("protected"), "{view}");
    assert_eq!(view["view"]["revision"], json!(2));
    // A second restore finds the row and writes nothing.
    assert_eq!(
        run(&writer(&home, "restore", &head))["restored"],
        Value::Null
    );
    assert_eq!(count(&home, "select count(*) from guard_events"), 1);
}

#[test]
fn a_restore_the_plan_refuses_writes_nothing() {
    let home = Home::new();
    let head = quarantined(&home);
    let reply = run(&ExtensionControlAuthorityRequestV1 {
        key_b64: None,
        ..writer(&home, "restore", &head)
    });
    assert_eq!(reply["fault"], json!("tampered"), "{reply}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_snapshot"
        ),
        0
    );
    assert_eq!(count(&home, "select count(*) from guard_events"), 0);
}

fn snapshot_digest(home: &Home, revision: i64) -> String {
    home.db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = ?",
            params![revision],
            |row| row.get(0),
        )
        .unwrap()
}

fn roll_back(home: &Home, anchor_json: &str, now: &str) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        revision: Some(1),
        snapshot_digest: Some(snapshot_digest(home, 1)),
        now: Some(now.to_owned()),
        ..writer(home, "roll_back", anchor_json)
    })
}

#[test]
fn roll_back_removes_only_a_stale_prepared_row_and_its_open_proofs() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    home.db
        .execute_batch(
            "insert into extension_control_authority_proof values ('open', 'm', 2, 'r', null);
             insert into extension_control_authority_proof values ('spent', 'm', 2, 'r', 'c');",
        )
        .unwrap();
    let transitions = "select count(*) from extension_control_authority_transition";
    // Inside the retry window the row is kept for its own request.
    assert_eq!(roll_back(&home, &head, SOON)["rolled_back"], json!(false));
    assert_eq!(count(&home, transitions), 2);
    assert_eq!(roll_back(&home, &head, NOW)["rolled_back"], json!(true));
    assert_eq!(count(&home, transitions), 1);
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof where proof_id_hash = 'spent'"
        ),
        1
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof"
        ),
        1
    );
    // Nothing is left to roll back.
    assert_eq!(roll_back(&home, &head, NOW)["rolled_back"], json!(false));
}

#[test]
fn roll_back_drops_the_rows_command_pack_reservation() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    home.db
        .execute_batch(
            "create table extension_command_pack_pending (control_revision integer primary key);
             insert into extension_command_pack_pending values (2);
             insert into extension_command_pack_pending values (7);",
        )
        .unwrap();
    assert_eq!(roll_back(&home, &head, NOW)["rolled_back"], json!(true));
    assert_eq!(
        count(
            &home,
            "select group_concat(control_revision) is '7' from extension_command_pack_pending"
        ),
        1
    );
}
