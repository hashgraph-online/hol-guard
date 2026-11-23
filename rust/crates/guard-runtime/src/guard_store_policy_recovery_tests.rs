//! Business-source recovery: the witness check, the install and the request
//! recovery marker.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::super::tests::{import_args, request_store, witness, NOW};
use super::recover_business_policy_source;
use crate::guard_store_args::Args;
use crate::guard_store_policy_upsert::tests::{dump, verifies_at};

const WITNESS: &str = "{\"anchor_digest\":\"d\"}";

fn replace_request(connection: &Connection, status: &str) {
    connection
        .execute(
            "update mcp_policy_requests set mode = 'replace', status = ?1",
            [status],
        )
        .unwrap();
}

fn recovery(request_id: &str) -> Value {
    json!({"request_id": request_id, "source_digest": "sha256:new"})
}

fn marker(connection: &Connection) -> Option<String> {
    connection
        .query_row(
            "select payload_json from sync_state \
             where state_key = 'business_policy_request_recovered_v1/r1'",
            [],
            |row| row.get(0),
        )
        .ok()
}

fn bare(expected: Option<&str>) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("now".into(), json!(NOW));
    args.insert("expected_witness".into(), json!(expected));
    args
}

#[test]
fn a_recovery_installs_the_source_and_records_the_request_in_one_write() {
    let connection = request_store();
    replace_request(&connection, "pending");
    let mut args = import_args("replace", Vec::new(), true);
    args.insert("expected_witness".into(), Value::Null);
    args.insert("business_witness".into(), json!(WITNESS));
    args.insert("recovery_request".into(), recovery("r1"));

    let reply = recover_business_policy_source(&connection, &Args(&args)).unwrap();

    assert_eq!(reply["installed"], json!(true));
    assert_eq!(reply["next_control_state"]["generation"], json!(4));
    assert_eq!(witness(&connection).as_deref(), Some(WITNESS));
    assert_eq!(
        marker(&connection).as_deref(),
        Some("{\"source_digest\": \"sha256:new\", \"request_recovered\": true}")
    );
    assert!(dump(&connection).iter().all(|row| verifies_at(row, 4)));
}

#[test]
fn a_recovery_over_a_committed_witness_only_records_the_request() {
    let connection = request_store();
    replace_request(&connection, "applied");
    connection
        .execute(
            "insert into sync_state values ('business_source_installation_v1', ?1, 'x')",
            [WITNESS],
        )
        .unwrap();
    let before = dump(&connection);
    let mut args = bare(Some(WITNESS));
    args.insert("recovery_request".into(), recovery("r1"));

    let reply = recover_business_policy_source(&connection, &Args(&args)).unwrap();

    assert_eq!(
        reply,
        json!({"installed": false, "next_control_state": null})
    );
    assert!(marker(&connection).is_some());
    assert_eq!(dump(&connection), before);
}

#[test]
fn a_moved_witness_is_refused_before_any_write() {
    let connection = request_store();
    replace_request(&connection, "pending");
    let before = dump(&connection);
    let mut args = import_args("replace", Vec::new(), true);
    args.insert("expected_witness".into(), json!(WITNESS));
    args.insert("business_witness".into(), json!(WITNESS));
    args.insert("recovery_request".into(), recovery("r1"));

    let error = recover_business_policy_source(&connection, &Args(&args)).unwrap_err();

    assert!(format!("{error:?}").contains("native_business_source_current_digest_changed"));
    assert_eq!(dump(&connection), before);
    assert_eq!(witness(&connection), None);
    assert_eq!(marker(&connection), None);
}

#[test]
fn a_changed_or_declined_request_is_not_marked_recovered() {
    let connection = request_store();
    for (status, request_id) in [("pending", "r1"), ("declined", "r1"), ("pending", "r9")] {
        // The fixture request is in `merge` mode until `replace_request`.
        if status == "declined" {
            replace_request(&connection, status);
        }
        let mut args = bare(None);
        args.insert("recovery_request".into(), recovery(request_id));
        let error = recover_business_policy_source(&connection, &Args(&args)).unwrap_err();
        assert!(format!("{error:?}").contains("candidate_digest_mismatch"));
    }
    assert_eq!(marker(&connection), None);
}
