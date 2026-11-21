//! Pins `queue_change`: a committed row's change event queued once, and
//! nothing queued for a row that never committed.

use guard_contracts::ExtensionControlAuthorityRequestV1;
use serde_json::{json, Value};

use super::super::tests::{catalog, local, run, with_cloud_events, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";

fn queue(home: &Home, revision: i64) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        revision: Some(revision),
        now: Some(NOW.to_owned()),
        ..home.request("queue_change", &catalog('a'))
    })
}

fn queued(home: &Home) -> i64 {
    home.db
        .query_row("select count(*) from guard_cloud_events", [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn the_committed_head_change_is_queued_once() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    let reply = queue(&home, 2);
    assert_eq!(reply["queued"], json!(2), "{reply}");
    let (event_type, payload): (String, String) = home
        .db
        .query_row(
            "select event_type, payload_json from guard_cloud_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(event_type, "policy.changed");
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["payload"]["revision"], json!(2));
    assert_eq!(payload["payload"]["previousRevision"], json!(1));
    assert_eq!(queue(&home, 2)["queued"], json!(2));
    assert_eq!(queued(&home), 1);
}

#[test]
fn nothing_is_queued_without_a_committed_row() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    for revision in [0, 2, 3] {
        let reply = queue(&home, revision);
        assert_eq!(reply["fault"], json!("tampered"), "{reply}");
    }
    assert_eq!(queued(&home), 0);
}
