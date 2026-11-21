//! The refusals of the op: what it will not record, and which stores it will
//! not touch.

use serde_json::{json, Value};

use super::evaluate_connector_setup_context_request;
use super::tests::{error_code, Fixture, CLI_ID};
use crate::local_store_read::SUPPORTED_SCHEMA_VERSION;

#[test]
fn a_missing_observation_or_another_identity_is_refused_without_a_write() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    let reply = fixture.call("local-cli.other-1", json!({"trigger_summary": "x"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_observation_missing"
    );
    let reply = fixture.call(
        CLI_ID,
        json!({"identity_hash": "cdcdcdcd", "trigger_summary": "x"}),
    );
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_identity_mismatch"
    );
    let written: Option<String> = fixture
        .connection
        .query_row(
            "select last_trigger_summary from local_cli_observation",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(written, None);
}

#[test]
fn invalid_requests_are_refused() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    let reply = fixture.call(CLI_ID, json!({"first_blocked_cause": "sudo"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_cause_invalid"
    );
    let reply = fixture.call(CLI_ID, json!({"trigger_summary": "x".repeat(5000)}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_request_invalid"
    );
    let reply = fixture.call("not-a-cli-id", json!({}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_request_invalid"
    );
    let reply = fixture.call(CLI_ID, json!({"identity_hash": "ab cd"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_request_invalid"
    );
    assert_eq!(fixture.stored_cause(CLI_ID), None);
}

#[test]
fn a_request_schema_mismatch_is_an_error() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    let mut request = fixture.request(CLI_ID, json!({}));
    request.schema = "guard-connector-setup-context-request.v0".to_owned();
    assert_eq!(
        evaluate_connector_setup_context_request(&request).unwrap_err(),
        "native_connector_setup_context_schema_mismatch"
    );
}

#[test]
fn a_store_that_is_not_this_schema_is_refused_without_a_write() {
    let newer = Fixture::at_version(SUPPORTED_SCHEMA_VERSION + 1);
    newer.observe(CLI_ID, "cli");
    let reply = newer.call(CLI_ID, json!({"first_blocked_cause": "connect_loopback"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_schema_unsupported"
    );
    assert_eq!(newer.stored_cause(CLI_ID), None);

    let older = Fixture::at_version(SUPPORTED_SCHEMA_VERSION - 1);
    older.observe(CLI_ID, "cli");
    let reply = older.call(CLI_ID, json!({"first_blocked_cause": "connect_loopback"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_schema_outdated"
    );
    assert_eq!(older.stored_cause(CLI_ID), None);

    let damaged = Fixture::new();
    damaged.observe(CLI_ID, "cli");
    damaged.marker(SUPPORTED_SCHEMA_VERSION, "not-the-checksum");
    let reply = damaged.call(CLI_ID, json!({"first_blocked_cause": "connect_loopback"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_schema_invalid"
    );
    assert_eq!(damaged.stored_cause(CLI_ID), None);

    let unmarked = Fixture::new();
    unmarked.observe(CLI_ID, "cli");
    unmarked
        .connection
        .execute("delete from local_cli_schema_migration", [])
        .unwrap();
    let reply = unmarked.call(CLI_ID, json!({"first_blocked_cause": "connect_loopback"}));
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_schema_outdated"
    );
}

#[test]
fn a_store_path_outside_guard_home_is_refused() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    let mut request = fixture.request(CLI_ID, json!({}));
    request.store_path = std::env::temp_dir()
        .join("elsewhere")
        .join("guard.db")
        .to_string_lossy()
        .into_owned();
    let reply: Value =
        serde_json::from_slice(&evaluate_connector_setup_context_request(&request).unwrap())
            .unwrap();
    assert_eq!(
        error_code(&reply),
        "native_connector_setup_context_path_invalid"
    );
}
