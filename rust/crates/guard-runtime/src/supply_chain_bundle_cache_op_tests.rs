use super::*;

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null, updated_at text not null);
             create table guard_supply_chain_bundle_cache (workspace_id text primary key, response_json text not null, cached_at text not null);",
        )
        .unwrap();
    connection
}

#[test]
fn no_cloud_workspace_reads_no_bundle() {
    assert_eq!(cached_bundle(&connection()).unwrap(), Value::Null);
}

#[test]
fn a_blank_workspace_id_reads_no_bundle() {
    let connection = connection();
    connection
        .execute(
            "insert into sync_state values ('oauth_local_credentials', '{\"workspace_id\":\"  \"}', 'now')",
            [],
        )
        .unwrap();
    assert_eq!(cached_bundle(&connection).unwrap(), Value::Null);
}

#[test]
fn the_workspace_bundle_is_read_from_its_cached_response() {
    let connection = connection();
    connection
        .execute_batch(
            "insert into sync_state values ('oauth_local_credentials', '{\"workspace_id\":\"ws-1\"}', 'now');
             insert into guard_supply_chain_bundle_cache values ('ws-1', '{\"bundle\":{\"rules\":[1]}}', 'then');
             insert into guard_supply_chain_bundle_cache values ('ws-2', '{\"bundle\":{\"rules\":[2]}}', 'then');",
        )
        .unwrap();
    assert_eq!(
        cached_bundle(&connection).unwrap(),
        serde_json::json!({"rules": [1]})
    );
}

#[test]
fn a_cached_response_without_a_bundle_reads_null() {
    let connection = connection();
    connection
        .execute_batch(
            "insert into sync_state values ('oauth_local_credentials', '{\"workspace_id\":\"ws-1\"}', 'now');
             insert into guard_supply_chain_bundle_cache values ('ws-1', '[]', 'then');",
        )
        .unwrap();
    assert_eq!(cached_bundle(&connection).unwrap(), Value::Null);
}

fn full_cache() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_supply_chain_bundle_cache (
                workspace_id text primary key, bundle_version text not null, key_id text not null,
                tier text not null, policy_hash text not null, feed_snapshot_hash text not null,
                scoring_version text not null, payload_hash text not null,
                response_json text not null, cached_at text not null);",
        )
        .unwrap();
    connection
}

fn response() -> Value {
    serde_json::json!({
        "bundle": {
            "bundleVersion": "v1",
            "keyId": "key-1",
            "tier": "premium",
            "policyHash": "p",
            "feedSnapshotHash": "f",
            "scoringVersion": 3,
            "rules": [1],
        },
        "payloadHash": "h",
    })
}

fn store_args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let args = store_args(args);
    dispatch(connection, method, &Args(&args))
}

fn column(connection: &Connection, name: &str) -> String {
    connection
        .query_row(
            &format!(
                "select {name} from guard_supply_chain_bundle_cache where workspace_id = 'ws-1'"
            ),
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn a_cached_response_is_written_with_its_columns_and_read_back() {
    let connection = full_cache();
    let answer = call(
        &connection,
        "cache_supply_chain_bundle",
        serde_json::json!({"workspace_id": "ws-1", "response": response(), "cached_at": "t1"}),
    )
    .unwrap();
    assert_eq!(answer, Value::Null);
    assert_eq!(column(&connection, "bundle_version"), "v1");
    assert_eq!(column(&connection, "tier"), "premium");
    assert_eq!(column(&connection, "scoring_version"), "3");
    assert_eq!(column(&connection, "payload_hash"), "h");
    let read = call(
        &connection,
        "get_cached_supply_chain_bundle",
        serde_json::json!({"workspace_id": "ws-1"}),
    )
    .unwrap();
    assert_eq!(read["cached_at"], "t1");
    let stored: Value = serde_json::from_str(read["response_json"].as_str().unwrap()).unwrap();
    assert_eq!(stored, response());
}

#[test]
fn a_second_write_replaces_the_workspace_row() {
    let connection = full_cache();
    let mut next = response();
    next["bundle"]["bundleVersion"] = Value::from("v2");
    for (body, at) in [(response(), "t1"), (next, "t2")] {
        call(
            &connection,
            "cache_supply_chain_bundle",
            serde_json::json!({"workspace_id": "ws-1", "response": body, "cached_at": at}),
        )
        .unwrap();
    }
    assert_eq!(column(&connection, "bundle_version"), "v2");
    assert_eq!(column(&connection, "cached_at"), "t2");
}

#[test]
fn a_workspace_without_a_row_reads_null() {
    let connection = full_cache();
    let read = call(
        &connection,
        "get_cached_supply_chain_bundle",
        serde_json::json!({"workspace_id": "ws-9"}),
    )
    .unwrap();
    assert_eq!(read, Value::Null);
}

#[test]
fn column_values_render_as_python_str_did() {
    assert_eq!(column_text(Some(&Value::from(7)), "k").unwrap(), "7");
    assert_eq!(column_text(Some(&Value::Bool(true)), "k").unwrap(), "True");
    assert_eq!(
        column_text(Some(&Value::Bool(false)), "k").unwrap(),
        "False"
    );
    assert_eq!(column_text(Some(&Value::Null), "k").unwrap(), "None");
    assert!(column_text(Some(&Value::from(1.5)), "k").is_err());
    assert!(column_text(Some(&serde_json::json!([1])), "k").is_err());
    assert!(column_text(None, "k").is_err());
}

#[test]
fn a_response_without_a_bundle_or_a_field_is_refused_and_nothing_is_written() {
    let connection = full_cache();
    let mut missing = response();
    missing["bundle"].as_object_mut().unwrap().remove("keyId");
    let mut no_hash = response();
    no_hash.as_object_mut().unwrap().remove("payloadHash");
    for body in [
        serde_json::json!({"bundle": []}),
        serde_json::json!({}),
        missing,
        no_hash,
    ] {
        let result = call(
            &connection,
            "cache_supply_chain_bundle",
            serde_json::json!({"workspace_id": "ws-1", "response": body, "cached_at": "t"}),
        );
        assert!(matches!(result, Err(StoreError::Value(_))), "{body}");
    }
    let rows: i64 = connection
        .query_row(
            "select count(*) from guard_supply_chain_bundle_cache",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn the_methods_are_routed_here() {
    for method in [
        "cached_supply_chain_bundle",
        "get_cached_supply_chain_bundle",
        "cache_supply_chain_bundle",
    ] {
        assert!(handles(method), "{method}");
    }
    assert!(!handles("add_guard_event_v1"));
}
